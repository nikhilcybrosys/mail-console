/* Settings > Appearance: keep the colour picker and the hex box in step, and let "Use the default" clear the colour. */
(function () {
  var text = document.getElementById("accent"), pick = document.getElementById("accent-picker"), clear = document.querySelector("[data-accent-clear]");
  if (!text || !pick) return;
  var HEX = /^#[0-9a-fA-F]{6}$/;
  function changed() { text.dispatchEvent(new Event("input", { bubbles: true })); }
  pick.addEventListener("input", function () { text.value = pick.value.toUpperCase(); changed(); });
  text.addEventListener("input", function () { if (HEX.test(text.value)) pick.value = text.value; });
  if (clear) clear.addEventListener("click", function () { text.value = ""; changed(); });
})();
