const logoutButton = document.getElementById("logout");
if (!logoutButton) {
    console.error("logoutButton is missing");
}
logoutButton?.addEventListener("click", () => {
    sessionStorage.removeItem("username");
    sessionStorage.removeItem("password");
    sessionStorage.removeItem("method");
})