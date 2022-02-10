clear

echo ------------------------------------------------------------------------

echo ---PLEASE MAKE SURE YOU HAVE ASSIGNED THE IP OF YOUR VPS TO A DOMAIN NAME. Use a service such as duckdns.org to achieve this.---


read -n 1 -s -r -p "Press any key to continue"


clear


echo Enter a valid gen4 UUID. Use UUIDGenerator.net to generate a gen4 UUID, and keep this UUID saved:
read UUID

echo Enter your e-mail address. Please make sure to enter a valid e-mail:
read MAILADD

echo Enter your registered domain name. Please make sure you have assigned your VPS IP to the domain name.:
read DOMAINNAME


systemctl stop xray

ufw disable

apt-get update -y

iptables -I INPUT -j ACCEPT
iptables -I OUTPUT -j ACCEPT




#rm -rf /etc/localtime
#cp /usr/share/zoneinfo/Asia/Colombo /etc/localtime
#date -R

#disable ubuntu firewall
ufw disable

#running xray install script for linux - systemd

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

#adding new configuration files 

rm -rf /usr/local/etc/xray/config.json
cat << EOF > /usr/local/etc/xray/config0.json
{
    "inbounds": [
	{
	"port": 80,
	"protocol": "vmess",
	"tag":"http",
	"settings": {
		"clients": [
					{
						"id": "$UUID",
						"level": 1,
						"alterId": 4,
						"security": "auto"
					}
		]
	},
	"streamSettings": {
		"network": "tcp",
		"tcpSettings": {
			"header": {
				"type": "http",
				"response": {
					"version": "1.1",
					"status": "200",
					"reason": "OK",
					"headers": {
						"Content-encoding": [
							"gzip"
						],
						"Content-Type": [
							"text/html; charset=utf-8"
						],
						"Cache-Control": [
							"no-cache"
						],
						"Vary": [
							"Accept-Encoding"
						],
						"X-Frame-Options": [
							"deny"
						],
						"X-XSS-Protection": [
							"1; mode=block"
						],
						"X-content-type-options": [
							"nosniff"
						]
					}
				}
			}
		}
	},
	"sniffing": {
		"enabled": true,
		"destOverride": [
			"http",
			"tls"
		]
	}
}
]
}
EOF
cat << EOF > /usr/local/etc/xray/config1.json
{
    "inbounds": [
	{
            "port": 443,
            "protocol": "vless",
			"tag":"XTLS",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-direct",
                        "level": 0
                    }
                ],
                "decryption": "none",
				"fallbacks": [
                    {
                        "dest": "www.baidu.com:80"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/xray.crt",
                            "keyFile": "/etc/xray/xray.key"
                        }
                    ]
                }
            }
        }
	]
}
EOF
cat << EOF > /usr/local/etc/xray/config2.json
{
    "outbounds": [
	{
      "protocol": "freedom",
      "settings": {}
    }
	]
}
EOF

#accuring a ssl certificate

apt-get update 
apt-get install curl -y 
apt-get install cron -y 
apt-get install socat -y

#curl https://get.acme.sh | sh -s email=$MAILADD

git clone https://github.com/acmesh-official/acme.sh.git
cd ./acme.sh
./acme.sh --install -m $MAILADD

bash ~/.acme.sh/acme.sh --register-account -m $MAILADD

bash ~/.acme.sh/acme.sh --set-default-ca  --server  letsencrypt

source ~/.bashrc

bash ~/.acme.sh/acme.sh --set-default-ca  --server  letsencrypt

bash ~/.acme.sh/acme.sh --register-account -m $MAILADD

bash ~/.acme.sh/acme.sh --issue -d $DOMAINNAME --alpn -k ec-256 --force

bash ~/.acme.sh/acme.sh --set-default-ca  --server  letsencrypt

mkdir /etc/xray && ~/.acme.sh/acme.sh --installcert -d $DOMAINNAME --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 644 /etc/xray/xray.key

#starting xray core on sytem startup

cat << EOF > /etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf
# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!  # Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray/
EOF
systemctl daemon-reload
systemctl enable xray
systemctl restart xray

#install bbr

mkdir ~/across
git clone https://github.com/teddysun/across ~/across
chmod 777 ~/across
bash ~/across/bbr.sh

clear
echo ------------------------------------------------------------------
echo SERVER HAS BEEN SETUP SUCCESFULLY!
echo Your UUID : $UUID
echo Your domain name : $DOMAINNAME
