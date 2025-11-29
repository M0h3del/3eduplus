<?php 

session_set_cookie_params([
    'lifetime' => 3600,  
    'path'     => '/',
    'domain'   => 'example.com',
    'secure'   => true,  
    'httponly' => true,   
    'samesite' => 'Strict'
]);


session_start();
require_once 'config.php';


$errors = [
    'login' => $_SESSION['login-error'] ?? '',
    'register' => $_SESSION['register-error'] ?? ''
];

$activeForm = $_SESSION['active_form'] ?? 'login';

function showError($error) {
    return !empty($error) ? "<p class='error-message'>$error</p>" : '';
}

function isActiveForm($formName, $activeForm) {
    return $formName === $activeForm ? 'active' : '';
}


if (isset($_POST['register'])) {
    $username = $_POST['name'];
    $email    = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $wilaya   = $_POST['wilaya'];
    $numero   = $_POST['numero_tlf_utilisateur'];
    $date     = $_POST['date_registration'];
    $image    = $_POST['image_utilisateur'];
    $gender   = $_POST['gender'];

    $checkEmail = $conn->query("SELECT Email FROM utilisateurs WHERE Email = '$email'");

    if ($checkEmail->num_rows > 0) {
        $_SESSION['register-error'] = 'Email already exists';
        $_SESSION['active_form'] = 'register';
        header("Location: signup.html");
        exit();
    } else {
        $stmt = $conn->prepare("INSERT INTO utilisateurs 
            (Nom_Complet, Mot_de_passe, Email, Wilaya, numero_tlf_utilisateur, date_registration, image_utilisateur, gender) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

        $stmt->bind_param("ssssisss", $username, $password, $email, $wilaya, $numero, $date, $image, $gender);
        $stmt->execute();
        $stmt->close();

        
        unset($_SESSION['register-error'], $_SESSION['active_form']);
        header("Location: login.html");
        exit();
    }
}


if (isset($_POST['login'])) {
    $email    = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM utilisateurs WHERE Email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['Mot_de_passe'])) {
          
         

            unset($_SESSION['login-error'], $_SESSION['active_form']);
            header("Location: dashboard.html");
            exit();
        } else {
            $_SESSION['login-error'] = 'Invalid email or password';
            $_SESSION['active_form'] = 'login';
            header("Location: login.html");
            exit();
        }
    } else {
        $_SESSION['login-error'] = 'Invalid email or password';
        $_SESSION['active_form'] = 'login';
        header("Location: login.html");
        exit();
    }
}
?>
