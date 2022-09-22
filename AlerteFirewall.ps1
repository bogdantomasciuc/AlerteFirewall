<# Alerte mail Firewall / Mail firewall alerts
    .Descriere (RO)
    Script pentru verificarea existentei de reguli de blocare acces gestionate de o aplicatie terta care monitorizeaza autentificari esuate. 
    Alertele se trimit pe email la doua adrese. 
    Se verifica inregistrarile adaugate in ultimele 5 minute. Scriptul ar trebui sa fie programat sa ruleze din 5 in 5 minute.
    .Description (EN)
    Script that checks periodically for new firewall rules added automatically by a third party application that monitors failed logins. 
    Alerts are sent to two email addresses.
    By default, checks are made for events added in the last 5 minutes. Script should be scheduled to run every 5 minutes.

    .Utilizare (RO)
    Modificati, dupa caz, numele clientului unde este activat script-ul si adresele email din variabilele $From, $To si $Cc.
    .Utilization (EN)
    Edit, accordingly, client name, email addresses and authentication data.
#>

$numeClient = "CLIENT/SERVER MONITORIZAT"; #client name
$From = "noreply@domeniulmeu.ro";
$To = "adresamea@adresadestinatar.ro”;
$Cc = "alerte@demeniulmeu.ro";
$IntervalMinuteVerificare = 5; #how many minutes in the past should we start looking for events?

# Date acces server email
$SMTPServer = "mail.domeniulmeu.ro";
$SMTPPort = "587";
$username = "noreply@domeniulmeu.ro";
$password = "oo0#Parola_mea_super_secreta!#0oo";
$secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
$SMTPCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd;

# Colectam informatiile necesare din log-ul Windows si le tinem intr-o lista
$Events = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; id=2004;} | Where-Object {$_.TimeCreated -le (Get-Date) -and $_.TimeCreated -ge (Get-Date).AddMinutes(-$IntervalMinuteVerificare)}; 
# Pregatim o lista noua pe care o vom popula mai tarziu
$FilteredEvents = @();
ForEach ($Event in $Events) {
    $eventXML = [xml]$Event.ToXml();
        For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
        Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text';
        }
        #Ne intereseaza doar evenimentele cu un anume nume din lista.
		    if ($Event.RuleName -like '*RDP Defender*') { 
        # Adaugam in lista noua doar evenimentele gasite
        $FilteredEvents = $FilteredEvents + $Event; 
        }
    
    }; 
if ($FilteredEvents) {
    # (RO) Avem evenimente noi asa ca pregatim mail
    # (EN) We have new events so we prepare an email message
    $Subject = "[$numeClient] [Alerta blocare firewall] O noua adresa IP a fost blocata pentru autentificari succesive esuate!";
	  $Body = "<h2>Alerta blocare IP pentru autentificari esuate</h2>";
    $Body += '<pre>';
    $Body += Out-String -InputObject ($FilteredEvents | Format-Table -Property TimeCreated,RuleName,RemoteAddresses -AutoSize);	
    $Body += '</pre>';
    $Body += “<h4>Server: <b>$numeClient</b></h4>”;
    # (RO) de decomentat pentru diagnosticare si de comentat linia Send-MaiMessage
    # (EN) uncomment next line to debug
    #echo $Subiect; 
    # (RO) de decomentat pentru diagnosticare si de comentat linia Send-MaiMessage
    # (EN) uncomment next line to debug
    #echo $Body; 
    # (RO) Trimitem email-ul pregatit
    # (EN) We send the email
    # (RO) de decomentat pentru diagnosticare
    # (EN) Comment next line to not actually send mail during debug
    Send-MailMessage -From $From -to $To -cc $Cc -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl -Credential $SMTPCredentials;
    exit;
    } else {
        # (RO) Nu sunt inregistrari noi.
        # (EN) There are no new events.
        exit;
        };
#Final / END
exit;
