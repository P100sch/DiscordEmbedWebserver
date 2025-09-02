"use strict";
const form = document.getElementById("uploadForm");
if (!(form instanceof HTMLFormElement)) {
    console.error("Could not find the form");
}
else {
    form.addEventListener("submit", (e) => {
        const overlay = document.getElementById("overlay");
        if (overlay) {
            overlay.style.removeProperty("display");
        }
    });
    form.addEventListener("error", (e) => {
        const overlay = document.getElementById("overlay");
        if (overlay) {
            overlay.style.setProperty("display", "none");
        }
    });
}
