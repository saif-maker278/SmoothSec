#!/bin/bash
fichier_regles='/etc/snort/et/local.rules'
if [[ -f $fichier_regles ]]; then
	echo "Les règles locales de SmoothSec:"
	cat $fichier_regles
else
	echo "Fichier des règles locales de SmoothSec n'est pas trouvé!"
fi
