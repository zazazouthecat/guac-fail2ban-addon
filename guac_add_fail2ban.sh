#######################################################################################################################
#!/bin/bash
#Script SBER v1.0 - 28/09/2023
#Script basé sur les sources https://github.com/itiligent/Guacamole-Install/blob/main/guac-optional-features/add-fail2ban.sh
# 
# - Script d'installation fail1ban pour guacamole
#######################################################################################################################


# Prepare text output colours
GREY='\033[0;37m'
DGREY='\033[0;90m'
GREYB='\033[1;37m'
LRED='\033[0;91m'
LGREEN='\033[0;92m'
LYELLOW='\033[0;93m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' #No Colour

clear

# Check if user is root or sudo
if ! [ $( id -u ) = 0 ]; then
    echo "Merci de lancer ce script en root ou sudo" 1>&2
    exit 1
else
	apt install sudo
	echo -e "Ajout de Root au sudoers"
	sudo usermod -aG sudo root
	echo
fi

# Initialise variables
FAIL2BAN_BASE=""
FAIL2BAN_GUAC=""
FAIL2BAN_NGINX=""
FAIL2BAN_SSH=""
TOMCAT_VERSION=$(ls /etc/ | grep tomcat)
fail2banbanTime=""
fail2banfindTime=""
fail2banmaxRetry=""
fail2bancustomIp=""
fail2banNotBanIpRange=""

#Clean up from any previous runs
rm -f /tmp/fail2ban.conf
rm -f /tmp/ip_list.txt
rm -f /tmp/netaddr.txt
rm -f /tmp/fail2ban.update

# Log Location
LOG="/tmp/guacamole_fail2ban_addon.log"

clear

#Prez !
clear
echo
echo
echo -e "${YELLOW} |'-._/\_.-'| ***************************************** |'-._/\_.-'| "
echo -e "${YELLOW} |    ||    | ***************************************** |    ||    | "
echo -e "${YELLOW} |___o()o___| ***************************************** |___o()o___| "
echo -e "${YELLOW} |__((<>))__| ********** BASTION DE SECURITE ********** |__((<>))__| "
echo -e "${YELLOW} \   o\/o   / **********   Apache Guacamole  ********** \   o\/o   /"
echo -e "${YELLOW}  \   ||   /  **********   Fail2Ban Add-On   **********  \   ||   /"
echo -e "${YELLOW}   \  ||  /   *****************************************   \  ||  /"
echo -e "${YELLOW}    '.||.'    **********************************SBER***    '.||.'"
echo -e "${YELLOW}      ''      *****************************************      ''"
echo
echo
# Fin de Prez !

#######################################################################################################################
# Start setup prompts #################################################################################################
#######################################################################################################################

# Prompt to install fail2ban base package with no policy as yet, default of yes
if [[ -z ${FAIL2BAN_BASE} ]]; then
    echo
    echo -e -n "${LGREEN}Voulez-vous installer la fonction Fail2Ban (Anti-BruteForce) ? (O/n): ${GREY}"
    read PROMPT
    if [[ ${PROMPT} =~ ^[Nn]$ ]]; then
        FAIL2BAN_BASE=false
    else
        FAIL2BAN_BASE=true
    fi
fi

# Prompt to install Guacamole fail2ban config defaults, default of no
if [[ -z ${FAIL2BAN_GUAC} ]] && [[ "${FAIL2BAN_BASE}" = true ]]; then
    echo -e -n "${YELLOW}POLICY: Voulez-vous appliquer la politique de sécurité Fail2Ban à Guacamole? (O/n):${GREY}"
    read PROMPT
    if [[ ${PROMPT} =~ ^[Nn]$ ]]; then
        FAIL2BAN_GUAC=false
    else
        FAIL2BAN_GUAC=true
    fi
fi

#######################################################################################################################
# Fail2ban base setup #################################################################################################
#######################################################################################################################

# Install base fail2ban base application, and whitelist the local subnet as the starting baseline (no policy defined yet)
if [[ "${FAIL2BAN_BASE}" = true ]]; then

    #Update and install fail2ban (and john for management of config file updates, and not overwrite any existing settings)
    apt-get update -qq >/dev/null 2>&1
    apt-get install fail2ban john -qq -y >/dev/null 2>&1

    # Create the basic jail.local template and local subnet whitelist
    cat >/tmp/fail2ban.conf <<EOF
[DEFAULT]
destemail = yourname@example.com
sender = yourname@example.com
action = %(action_mwl)s
ignoreip =
EOF

    # We need to discover all interfaces to ascertain what network ranges to add to fail2ban "ignoreip" policy override defaults
    ip -o addr show up primary scope global | while read -r num dev fam addr rest; do echo ${addr%*}; done | cat >/tmp/ip_list.txt

    # Loop the list of discovered ips and extract the subnet ID addresses for each interface
    FILE=/tmp/ip_list.txt
    LINES=$(cat $FILE)
    for LINE in $LINES; do

        tonum() {
            if [[ $LINE =~ ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+) ]]; then
                addr=$(((${BASH_REMATCH[1]} << 24) + (${BASH_REMATCH[2]} << 16) + (${BASH_REMATCH[3]} << 8) + ${BASH_REMATCH[4]}))
                eval "$2=\$addr"
            fi
        }
        toaddr() {
            b1=$((($1 & 0xFF000000) >> 24))
            b2=$((($1 & 0xFF0000) >> 16))
            b3=$((($1 & 0xFF00) >> 8))
            b4=$(($1 & 0xFF))
            eval "$2=\$b1.\$b2.\$b3.\$b4"
        }

        if [[ $LINE =~ ^([0-9\.]+)/([0-9]+)$ ]]; then
            # CIDR notation
            IPADDR=${BASH_REMATCH[1]}
            NETMASKLEN=${BASH_REMATCH[2]}
            PREFIX=$NETMASKLEN
            zeros=$((32 - NETMASKLEN))
            NETMASKNUM=0
            for ((i = 0; i < $zeros; i++)); do
                NETMASKNUM=$(((NETMASKNUM << 1) ^ 1))
            done
            NETMASKNUM=$((NETMASKNUM ^ 0xFFFFFFFF))
            toaddr $NETMASKNUM NETMASK
        else
            IPADDR=${1:-192.168.1.1}
            NETMASK=${2:-255.255.255.0}
        fi

        tonum $IPADDR IPADDRNUM
        tonum $NETMASK NETMASKNUM

        # The logic to calculate network and broadcast
        INVNETMASKNUM=$((0xFFFFFFFF ^ NETMASKNUM))
        NETWORKNUM=$((IPADDRNUM & NETMASKNUM))
        BROADCASTNUM=$((INVNETMASKNUM | NETWORKNUM))

        toaddr $NETWORKNUM NETWORK
        toaddr $BROADCASTNUM BROADCAST

        # Reverse engineer the subnet ID from the calcualted IP address and subnet prefix
        IFS=. read -r i1 i2 i3 i4 <<<"$IPADDR"
        IFS=. read -r m1 m2 m3 m4 <<<"$NETMASK"

        # Lay out the subnet ID address as a variable
        printf -v NETADDR "%d.%d.%d.%d" "$((i1 & m1))" "$((i2 & m2))" "$((i3 & m3))" "$((i4 & m4))"

        #Dump out the calcualted subnet IDs to a file
        echo $NETADDR"/"$NETMASKLEN | tr '\n' ' ' | cat >>/tmp/netaddr.txt

    done

fi

if [[ "${FAIL2BAN_BASE}" = true ]]; then
[ -z "${fail2banbanTime}" ] \
	&& read -p "Entrez le nombre de minutes ou l'ip sera bannie (Ex : 15 ): " fail2banbanTime
	[ -z "${fail2banmaxRetry}" ] \
	&& read -p "Entrez le nombre maximum autorisé de tentative de mot de passe (Ex : 5) : " fail2banmaxRetry
	[ -z "${fail2banfindTime}" ] \
	&& read -p "Entrez le laps de temps autorisé pour faire le maximum de tentative (Ex : 10 , Si 5 essais en < 10min = Ban) : " fail2banfindTime
	
	echo -e "${CYAN}Ajout de regle, pour empêcher les ip locales d'être bannies"

	if [[ -z ${fail2bancustomIp} ]]; then
			echo -e -n "${CYAN}Voulez-vous configurer une plage d'ip perso en plus de celle par défaut ? (O/n): ${GREY}"
			read PROMPT
			if [[ ${PROMPT} =~ ^[Nn]$ ]]; then
				fail2bancustomIp=false
			else
				fail2bancustomIp=true
			fi
	fi
	if [ "${fail2bancustomIp}" = true ]; then
		[ -z "${fail2banNotBanIpRange}" ] \
		&& read -p "Entrez la plage d'ip a exclure (Ex : 172.16.0.0/16): " fail2banNotBanIpRange
	fi
	
    # Now the above loop is done, append the single loopback address to all the discovered the subnet IDs in a single line
    sed -i 's/^/127.0.0.1\/24 /' /tmp/netaddr.txt

    # Finally assemble the entire syntax of the ignoreip whitelist for insertion into the base fail2ban config
    SED_IGNORE=$(echo "ignoreip = ")
    SED_NETADDR=$(cat /tmp/netaddr.txt)
    sed -i "s|ignoreip \=|${SED_IGNORE}${SED_NETADDR}${fail2banNotBanIpRange}|g" /tmp/fail2ban.conf

    # Move the new base fail2ban config to the jail.local file
    touch /etc/fail2ban/jail.local

    # Apply the base config, keeping any pre-existing settings
    sudo bash -c 'cat /tmp/fail2ban.conf /etc/fail2ban/jail.local | unique /tmp/fail2ban.update ; cat /tmp/fail2ban.update > /etc/fail2ban/jail.local'

    # Clean up
    rm -f /tmp/fail2ban.conf
    rm -f /tmp/ip_list.txt
    rm -f /tmp/netaddr.txt
    rm -f /tmp/fail2ban.update

    # bounce the service to reload the new config
    systemctl restart fail2ban

    # Done
    echo
    echo -e "${LGREEN}Fail2ban installé...${GREY}"
    echo

else
    echo -e "${LGREEN}Fail2ban installation annulée.${GREY}"

fi

#######################################################################################################################
# Fail2ban optional policy setup items ################################################################################
#######################################################################################################################
if [[ "${FAIL2BAN_GUAC}" = true ]]; then

#On transforme les minustes de fail2banbanTime en secondes
fail2banbanTime=$((fail2banbanTime*60))
#On transforme les minustes de fail2banfindTime en secondes
fail2banfindTime=$((fail2banfindTime*60))

    # Create the Guacamole jail.local policy template
    cat >/tmp/fail2ban.conf <<EOF
[guacamole]
enabled = true
port = http,https
logpath  = /var/log/$TOMCAT_VERSION/catalina.out
bantime = ${fail2banbanTime}
findtime  = ${fail2banfindTime}
maxretry = ${fail2banmaxRetry}
EOF

    # Apply the new Guacamole jail config keeping any pre-existing settings
    sudo bash -c 'cat /tmp/fail2ban.conf /etc/fail2ban/jail.local | unique /tmp/fail2ban.update ; cat /tmp/fail2ban.update > /etc/fail2ban/jail.local'

    # Backup the default Fail2ban Guacamole filter
    cp /etc/fail2ban/filter.d/guacamole.conf /etc/fail2ban/filter.d/guacamole.conf.bak

    # Remove the default log search regex
    sudo bash -c 'sed -e "/Authentication attempt from/ s/^#*/#/" -i /etc/fail2ban/filter.d/guacamole.conf'

    # Create a new log search regex specific for tomcat logs (as a variable due to complexity of characters for sed syntax)
    REGEX='failregex = ^.*WARN  o\.a\.g\.r\.auth\.AuthenticationService - Authentication attempt from <HOST> for user "[^"]*" failed\.$'
    #Insert the new regex
    sed -i -e "/Authentication attempt from/a ${REGEX}" /etc/fail2ban/filter.d/guacamole.conf

    # Done
    echo -e "${LGREEN}Politique de sécurité Guacamole appliquée ${CYAN}\n- ${SED_NETADDR} ${fail2banNotBanIpRange} sont sur la liste blanche de toutes les interdictions IP.\n- Pour modifier cette liste blanche, editer /etc/fail2ban/jail.local & sudo systemctl restart fail2ban \n"

    # Bounce the service to reload the new config
    systemctl restart fail2ban
    echo
fi

# Clean up
rm -f /tmp/fail2ban.conf
rm -f /tmp/ip_list.txt
rm -f /tmp/netaddr.txt
rm -f /tmp/fail2ban.update


#Done
echo
echo "Terminé !"
echo -e ${NC}
