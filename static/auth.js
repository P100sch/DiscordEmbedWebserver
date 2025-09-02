"use strict";
const logoutButton = document.getElementById("logout");
if (!logoutButton) {
    console.error("logoutButton is missing");
}
logoutButton === null || logoutButton === void 0 ? void 0 : logoutButton.addEventListener("click", () => {
    sessionStorage.removeItem("username");
    sessionStorage.removeItem("password");
    sessionStorage.removeItem("method");
});
