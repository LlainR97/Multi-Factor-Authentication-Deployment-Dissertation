document.getElementById('signupForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('errorMsg');

    // Password validation: min 8 chars, 1 number, 1 special char
    const regex = /^(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z0-9!@#$%^&*]{8,}$/;

    if (!regex.test(password)) {
        errorMsg.textContent = "Password does not meet requirements.";
    } else {
        errorMsg.textContent = "";
        alert("Sign-Up successful! Redirecting to Login...");
        window.location.href = "login.html"; // Next page
    }
});
