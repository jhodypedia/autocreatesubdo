// public/js/app.js
document.addEventListener('DOMContentLoaded', () => {
  // deter basic devtools & right click (not secure but deterrent)
  document.addEventListener('contextmenu', e => { /* e.preventDefault(); */ });
  document.addEventListener('keydown', function(e){
    if (e.keyCode === 123) e.preventDefault(); // F12
    if (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) e.preventDefault();
    if (e.ctrlKey && e.keyCode === 85) e.preventDefault();
  });
});
