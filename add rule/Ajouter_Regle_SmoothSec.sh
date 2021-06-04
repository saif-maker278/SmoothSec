#!/bin/bash

## Le manuel se trouve à:
## http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node27.html

function check_action()
{
	# Les actions que Snort effectue quand les critères dans une règle sont détectés dans le trafic
	local action=$1
	[[ $action = "alert" || $action = "log" || $action = "pass" || $action = "drop" || $action = "reject" || $action = "sdrop" || $action = "activate" || $action = "dynamic" ]]
	if [[ $? = 1 ]]; then
		echo "L'argument action est invalide. Veuillez choisir parmi alert, log, pass, drop, reject, sdrop, activate et dynamic."
		return 1
	else
		return 0
	fi
}
function check_protocol()
{
	# Snort supporte 4 protocols suivants
	local protocol=$1
	[[ $protocol = "tcp" || $protocol = "udp" || $protocol = "icmp" || $protocol = "ip" ]]
	if [[ $? = 1 ]]; then
		echo "L'argument protocol est invalide. Veuillez choisir parmi tcp, udp, icmp et ip."
		return 1
	else
		return 0
	fi
}
function check_ip() {
	local ip=$1
	# Contrôler si l'adresse IP est bien saisie
	# Pour une règle dans Snort, on peut mettre une adress IP classique pour parler d'elle même
	# ou ajouter un point d'exclamation ! devant pour parler de toutes autres adresses, sauf elle
	# Ici on regarde s'il y a un ! au debut, puis chaque bloc, divise par un point . , qui doit avoir la valeur
	# entre 0 et 255
	# L'adresse IP peut etre "any" pour toutes
	if [[ $ip = "any" ]]; then
		return 0
	fi
	[[ $1 =~ ^(\!?)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]
	return $?
	
}
function check_reseau()
{
	# Pour un réseau, on utilise la notation CIDR, par exemple: 192.168.1.0/24
	# Pareil que l'adresse IP, on peut mettre un ! pour exclure le reseau en question
	# C'est assez simple, on divise le input par /, puis controler la 1ere partie si elle est bien une adresse IP
	# et la 2e si elle est inferieure a 33
	# Le reseau peut être "any" pour tous
	local reseau=$1
	if [[ $reseau = "any" ]]; then
		return 0
	fi
	OIFS=$IFS
	IFS='/'
	local tabs=($reseau)
	IFS=$OIFS
	ip=${tabs[0]}
	local masque=${tabs[1]}
	check_ip $ip && [[ $masque =~ ^[0-9]{1,2}$ && $masque -le 32 ]];
	return $?
}
function check_port()
{
	# Dans une règle de Snort, le port peut être "any" pour dire tous les ports
	local port=$1
	if [[ $port = "any" ]]; then
		return 0
	fi
	# Ou un port unique,
	if [[ $port =~ ^([0-9]+)$ && $port -le 65535 ]]; then
		return 0
	fi
	# ou une intervalle de port. Dans le dernier cas, on peut trouver:
	# 1:10000 pour tous les ports entre 1 et 10000
	if [[ $port =~ ^([0-9]+):([0-9]+)$ ]]; then
		OIFS=$IFS
		IFS=':'
		local ports=($port)
		IFS=$OIFS
		[[ ${ports[0]} -le 65535 && ${ports[1]} -le 65535 && ${ports[0]} -le ${ports[1]} ]]
		if [[ $? = 1 ]]; then
			echo "Port invalide."
			return 1
		else
			return 0
		fi
	fi
	# :1024 pour tous les ports inferieurs à 1024
	if [[ $port =~ ^:([0-9]+)$ ]]; then
		OIFS=$IFS
		IFS=':'
		local ports=($port)
		IFS=$OIFS
		[[ ${ports[1]} -le 65536 ]]
		if [[ $? = 1 ]]; then
			echo "Port invalide."
			return 1
		else
			return 0
		fi
	fi
	# 5000: pour tous les ports superieurs à 5000
	if [[ $port =~ ^([0-9]+):$ ]]; then
		OIFS=$IFS
		IFS=':'
		local ports=($port)
		IFS=$OIFS
		[[ ${ports[0]} -le 65536 ]]
		if [[ $? = 1 ]]; then
			echo "Port invalide."
			return 1
		else
			return 0
		fi
	fi
	
	echo "Port invalide"
	return 1

}
function check_direction()
{
	# On peut appliquer une règle dans une direction unique ou dans les deux sens
	local direction=$1
	[[ $direction = "->" || $direction = "<>" ]]
	if [[ $? = 1 ]]; then
		echo "L'argument direction est invalide. Veuillez choisir entre -> et <>."
		return 1
	else
		return 0
	fi
}
function check_sid()
{
	local sid=$1
	if [[ ! $sid =~ ^[0-9]+$ ]]; then
		echo "SID doit etre un entier"
		return 1
	elif [[ $sid -le 1000000 ]]; then
		echo "SID doit être supérieur à 1 000 000, car les moins de 1000000 sont reservés"
		return 1
	else
		return 0
	fi
}
action=$1
protocol=$2
source=$3
port_source=$4
direction=$5
destination=$6
port_destination=$7
message=$8
sid=$9
option=${10}

if ! check_action $action || ! check_protocol $protocol || ! (check_ip $source || check_reseau $source) || ! check_port $port_source || ! check_direction $direction || ! (check_ip $destination || check_reseau $source) || ! check_port $port_destination || ! check_sid $sid; then
	echo "Un ou plusieurs arguments sont invalides."
	exit 1
fi
echo "Les arguments semblent bons..."
regle="$action $protocol $source $port_source $direction $destination $port_destination (msg: "$message"; $option sid:$sid;)"
fichier="/etc/snort/et/local.rules"
sid_msg="/etc/snort/et/sid-msg.map"
if [[ ! -f $fichier ]]; then
	echo "Le fichier $fichier n'est pas trouvé."
	exit 1
else
	echo "La règle à écrire:"
	echo $regle
	echo $regle >> $fichier
	if [[ -f $sid_msg ]]; then
		entree="$sid || $message"
		echo $entree >> $sid_msg
	fi
	echo "Nouvelle règle ajoutée."
	exit 0
fi

