#!/bin/bash
fichier="/etc/snort/et/local.rules"
sid_msg="/etc/snort/et/sid-msg.map"
if [[ ! -f $fichier ]]; then
	echo "Fichier $fichier n'est pas trouvé!"
	exit 1
fi
if [[ -z $1 ]]; then
	echo "Veuillez donner un sid"
	exit 1
fi
sid_a_supprimer=$1
if ! grep -q "sid:$sid_a_supprimer;" $fichier; then
	echo "La règle avec SID $sid_a_supprimer n'existe pas!"
	exit 1
fi
sed -i "/sid:$sid_a_supprimer/d" $fichier
sed -i "/^$sid_a_supprimer ||/d" $sid_msg
echo "La règle avec SID $sid_a_supprimer a été suppriméee"

