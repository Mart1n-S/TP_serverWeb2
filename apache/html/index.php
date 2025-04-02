<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Interface de Dons <?php echo(getenv('HO')); ?> </title>
    <!-- Intégration de Bootstrap -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/themes/prism.min.css" rel="stylesheet" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/prism.min.js"></script>
</head>
<body>
<body>
    <!-- Navigation / Header (optionnel) -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold" href="#">DonSecure</a>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row">
            <div class="col-md-8 offset-md-2">
    <img src="ds.jpg" alt="Logo DonSecure">
                <h1 class="display-4 mb-4">Bienvenue sur DonSecure</h1>
                <p class="lead">
                    Chers donateurs, nous sommes ravis de vous accueillir sur 
                    <strong>DonSecure</strong>, une plateforme de dons en ligne sécurisée, 
                    initiée par les YouTubers <em>Squizze</em> et <em>Mitchou</em> pour 
                    soutenir des causes qui nous tiennent à cœur. Grâce à votre générosité, 
                    nous pouvons collecter des fonds pour des projets solidaires, culturels 
                    et humanitaires.
                </p>
                <p>
                    Notre objectif est de rendre la charité et la solidarité accessibles à tous, 
                    tout en protégeant vos informations sensibles. En utilisant 
                    <strong>DonSecure</strong>, vous contribuez à une communauté engagée où 
                    chaque geste compte.
                </p>
                <p>
                    En un seul clic, vous pouvez faire la différence : ensemble, bâtissons 
                    un avenir meilleur, plus juste et plus responsable. Merci pour votre 
                    confiance et votre soutien généreux.
                </p>
                <p>
                    <em>— L’équipe DonSecure</em>
                </p>
                <a class="btn btn-primary btn-lg" href="#">Faire un don</a>
            </div>
        </div>
    </div>


<div class="container mt-5">
    <h2>Formulaire de Dons  - DonSecure</h2>
<form id="paymentForm">
    <div class="form-group">
        <label for="cardNumber">Numéro de Carte</label>
        <input 
            type="text" 
            class="form-control" 
            id="cardNumber" 
            placeholder="Numéro de carte de crédit" 
            required
            value="1234567890123456"
        >
    </div>
    <div class="form-group">
        <label for="cardExp">Date d'Expiration</label>
        <input 
            type="text" 
            class="form-control" 
            id="cardExp" 
            placeholder="MM/AA" 
            required
            value="12/24"
        >
    </div>
    <div class="form-group">
        <label for="cardCvv">CVV</label>
        <input 
            type="text" 
            class="form-control" 
            id="cardCvv" 
            placeholder="CVV" 
            required
            value="123"
        >
    </div>
    <div class="form-group">
        <label for="montant">Montant</label>
        <input 
            type="text" 
            class="form-control" 
            id="montant" 
            placeholder="montant" 
            required
            value="10"
        >
    </div>
    <div class="form-group">
        <label for="nom">Pseudo</label>
        <input 
            type="text" 
            class="form-control" 
            id="nom" 
            placeholder="Pseudo" 
            required
            value="Mitchou"
        >
    </div>
    <button type="submit" class="btn btn-primary">Soumettre</button>
</form>
    
<div id="response" class="mt-3"></div>
    <div id="response2" class="mt-3"></div>
</div>

<script>
document.getElementById('paymentForm').addEventListener('submit', function(event) {
    event.preventDefault();

    var cardNumber = document.getElementById('cardNumber').value;
    var cardExp = document.getElementById('cardExp').value;
    var cardCvv = document.getElementById('cardCvv').value;

    fetch('authCB.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `creditcard_number=${cardNumber}&creditcard_exp=${cardExp}&creditcard_cvv=${cardCvv}`
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
    })
    .catch((error) => {
        console.error('Error:', error);
    });
});

document.getElementById('paymentForm').addEventListener('submit', function(event) {
    event.preventDefault();

    var cardNumber = document.getElementById('cardNumber').value;
    var cardExp = document.getElementById('cardExp').value;
    var cardCvv = document.getElementById('cardCvv').value;
    var montant = document.getElementById('montant').value;
    var nom = document.getElementById('nom').value;

    fetch('sqlauthCB.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `creditcard_number=${encodeURIComponent(cardNumber)}&creditcard_exp=${encodeURIComponent(cardExp)}&creditcard_cvv=${encodeURIComponent(cardCvv)}&montant=${encodeURIComponent(montant)}&nom=${encodeURIComponent(nom)}`
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('response2').innerHTML = data; // La réponse peut maintenant être affichée directement
    })
    .catch((error) => {
        console.error('Error:', error);
    });
});

</script>
</body>
</html>

