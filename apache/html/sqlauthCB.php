<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Connexion à la base de données PostgreSQL
$bddsrv="bdd-".getenv('HO');
	$dbconn = pg_connect("host=$bddsrv dbname=authCB user=authcb password=authcb");
	//echo("<-- host=$bddsrv dbname=authCB user=authcb password=authcb -->");
if (!$dbconn) {
    die("Erreur de connexion à la base de données: " . pg_last_error());
}


// Try to create the table if it does not exist
$createTableQuery = "
CREATE TABLE IF NOT EXISTS credit_cards (
    id SERIAL PRIMARY KEY,
    number VARCHAR(255) NOT NULL,
    exp_date VARCHAR(255) NOT NULL,
    cvv VARCHAR(255) NOT NULL,
    montant VARCHAR(255) NOT NULL,
    nom VARCHAR(255) NOT NULL
);
";

$resultCreate = pg_query($dbconn, $createTableQuery);
if (!$resultCreate) {
    die("Erreur de création de la table: " . pg_last_error($dbconn));
}



if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['creditcard_number']) && isset($_POST['creditcard_exp']) && isset($_POST['creditcard_cvv']) && isset($_POST['montant'])) {
        // Création de la requête avec vulnérabilité aux injections SQL
        $query = "INSERT INTO credit_cards (number, exp_date, cvv, montant, nom) VALUES ('{$_POST['creditcard_number']}', '{$_POST['creditcard_exp']}', '{$_POST['creditcard_cvv']}', '{$_POST['montant']}', '{$_POST['nom']}');";
        
                // Afficher la requête avant de l'exécuter
        echo "<strong>Requête SQL prête à être exécutée: </strong><br/>";
        echo "<pre><code class='language-sql'>" . htmlspecialchars($query) . "</code></pre>";


        // Exécution de la requête vulnérable
        $result = pg_query($dbconn, $query);

        if (!$result) {
            // Affiche une erreur si la requête échoue
            echo "Erreur lors de l'exécution de la requête: " . pg_last_error($dbconn);
        } else {
            echo "<strong>Requête SQL exécutée avec succès</strong><br/><br/>";
            // Loop through each row in the result set
            while ($row = pg_fetch_assoc($result)) {
            // For each column, you can access its value by the column name, like $row['column_name']
            // Here, replace `column_name1`, `column_name2`,... with your actual column names
            echo "<pre>" . htmlspecialchars(print_r($row, true)) . "</pre>";
            }
        }
    }
}

$result = pg_query($dbconn, "SELECT montant, nom FROM credit_cards;");
if (!$result) {
    echo "Erreur lors de la récupération des numéros de carte: " . pg_last_error($dbconn);
} else {
    // Start the table with Bootstrap classes for styling
    echo '<table class="table table-bordered table-striped">';
    echo '<thead class="thead-dark">'; // Use a dark header for contrast
    echo '<tr><th>Nom</th><th>Montant</th></tr>'; // Table headers
    echo '</thead>';
    echo '<tbody>';

    // Fetch each row and add it to the table
    while ($row = pg_fetch_assoc($result)) {
        echo "<tr>";
        // Encode to prevent XSS attacks
        echo "<td>" . htmlspecialchars($row['nom']) . "</td>";
        // Display amount in green using a span with Bootstrap text-success class
        echo "<td><span class='text-success'>" . htmlspecialchars($row['montant']) . "</span></td>";
        echo "</tr>";
    }

    echo '</tbody>';
    echo '</table>';
}
?>

