# Proving the console roles cannot send mail

Run these as a human with `iam:SimulatePrincipalPolicy` in the mail-console account.
They only call the IAM simulator (no mail is sent, no state changes). Replace
`ACCOUNT` and the prefix (`mc-staging` or `mc-prod`). `simulate-principal-policy`
evaluates identity policies AND the permissions boundary.

```bash
export AWS_REGION=ap-south-1
ACCOUNT=000000000000
PREFIX=mc-prod
ID_ARN=arn:aws:ses:ap-south-1:$ACCOUNT:identity/example.com
SEND="ses:SendEmail ses:SendBulkEmail ses:SendRawEmail ses:SendTemplatedEmail ses:SendBulkTemplatedEmail ses:SendCustomVerificationEmail ses:SendBounce"

for ROLE in console-web console-worker console-write-ops console-write-security ecs-execution; do
  echo "== $ROLE: every line must be explicitDeny (or implicitDeny)"
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::$ACCOUNT:role/$PREFIX-$ROLE \
    --action-names $SEND \
    --resource-arns "$ID_ARN" \
    --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
done
```

Expected: `explicitDeny` for all seven actions on every role. Any `allowed` is a failure.

## Positive controls (the roles still do their job)

```bash
# web: read yes, write no
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/$PREFIX-console-web \
  --action-names ses:GetAccount ses:ListSuppressedDestinations ses:DeleteSuppressedDestination ses:PutEmailIdentityDkimAttributes \
  --resource-arns '*' --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
# expected: GetAccount allowed, ListSuppressedDestinations allowed, the two writes implicitDeny

# write-ops: needs SourceIdentity in the session (simulate it with a context entry)
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/$PREFIX-console-write-ops \
  --action-names ses:DeleteSuppressedDestination --resource-arns '*' \
  --context-entries ContextKeyName=aws:SourceIdentity,ContextKeyValues=operator@example.com,ContextKeyType=string \
                    ContextKeyName=aws:RequestedRegion,ContextKeyValues=ap-south-1,ContextKeyType=string \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
# expected: allowed. Repeat WITHOUT the SourceIdentity entry: expected implicitDeny.

# write-ops must not touch identities
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/$PREFIX-console-write-ops \
  --action-names ses:DeleteEmailIdentity --resource-arns "$ID_ARN" \
  --context-entries ContextKeyName=aws:SourceIdentity,ContextKeyValues=operator@example.com,ContextKeyType=string \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
# expected: implicitDeny
```

## Region fence

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/$PREFIX-console-web \
  --action-names ses:GetAccount --resource-arns '*' \
  --context-entries ContextKeyName=aws:RequestedRegion,ContextKeyValues=us-east-1,ContextKeyType=string \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
# expected: explicitDeny (boundary)
```

## Trust check (who may assume the write roles)

```bash
aws iam get-role --role-name $PREFIX-console-write-security --query 'Role.AssumeRolePolicyDocument'
# expected: Principal = the console-web role ARN only; Condition sts:SourceIdentity StringLike *@example.com
```

After the first real staging write, confirm in CloudTrail that `userIdentity.sessionContext.sourceIdentity`
holds the acting user's e-mail. Note: the simulator is a model, not proof; the final proof is the staging
test where a real `SendEmail` attempt with the web task credentials returns AccessDenied.
