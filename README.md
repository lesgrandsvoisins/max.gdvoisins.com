# max.gdvoisins.com

Configuration Nixos du serveur Paris le Nuage de Marjan JANJIC sous nixos. 

<https://max.gdvoisins.com>

## Installation

```bash
sudo su -
git clone git@github.com:lesgrandsvoisins/max.gdvoisins.com.git
for i in nixos dashy
    do
    echo $i
    mv /etc/$i{,.bak}
    ln -s /root/max.gdvoisins.com/etc/$i /etc/$i
done
```
