#!/bin/bash

url="$1"
GITHUB_API_KEY=""
SHODAN_API_KEY=""

create_folders(){
        if [ ! -d "$url" ]; then
    mkdir $url
    fi
        if [ ! -d "$url/subdomains" ]; then
    mkdir $url/subdomains
    fi
    if [ ! -d "$url/scrape" ]; then
    mkdir $url/scrape
    fi
    if [ ! -d "$url/vulns" ]; then
    mkdir $url/vulns
    fi
    if [ ! -d "$url/js" ]; then
    mkdir $url/js
    fi
}

harvesting_subdomains(){
    echo "[+] Harvesting subdomains with subfinder..."
    subfinder -d $url -o $url/subdomains/subfinder-out.txt

    echo "[+] Harvesting subdomains with github-subdomains..."
    github-subdomains -d $url -o $url/subdomains/gsd-out.txt -t $GITHUB_API_KEY

    echo "[+] Harvesting subdomains with shosubgo..."
    shosubgo -d $url -s $SHODAN_API_KEY | tee -a $url/subdomains/shosubgo-out.txt

    echo "[+] Harvesting subdomains with haktails..."
    echo $url | haktrails subdomains | tee -a $url/subdomains/haktrails-out.txt

    cat $url/subdomains/*-out.txt | sort -u >> $url/subdomains/subdomains.txt
}

url_scrape(){
        echo "[+] Scraping urls with gau..."
        echo $url | gau | tee -a $url/scrape/gau-out.txt

        echo "[+] Scraping urls with waymore..."
        python3  ~/tools/waymore/waymore.py -i $url -mode U -f -oU $url/scrape/waymore-out.txt

        echo "[+] Scraping urls with katana..."
        katana -silent -list $url -jc -kf all -d 2 -o $url/scrape/katana-out.txt

        echo "[+] Scraping urls with github-endpoints..."
        github-endpoints -q -k -d $url -t $GITHUB_API_KEY -o $url/scrape/ghendpoint-out.txt

        echo "[+] Creating url_extract.txt"
        cat $url/scrape/*-out.txt | sort -u >> $url/scrape/url_extract.txt

        echo "[+]creating JS files"
        cat $url/scrape/url_extract.txt | grep "${url}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | grep -aEi "\.(js)" | anew -q $url/js/url_extract_js.txt
}

js_analysis(){
        echo "[+] Subjs"
        cat $url/js/url_extract_js.txt | subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 | grep "$url" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q $url/js/subjslinks.txt
        cat $url/js/subjslinks.txt | grep -iE "\.js($|\?)" | anew -q $url/js/url_extract_js.txt

        echo "[+] Probing JS files with httpx..."
        cat $url/js/url_extract_js.txt | httpx -follow-redirects -random-agent -silent -status-code -content-type -retries 2 -no-color | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q $url/js/js_livelinks.txt

        echo "Gathering endpoints with xnLinkFinder"
        python3 ~/tools/xnLinkFinder/xnLinkFinder.py -i $url/js/js_livelinks.txt -sf $url/subdomains/subdomains.txt -o $url/js/js_endpoints.txt

        echo "[+] Gathering secrets with Mantra"
        cat $url/js/js_livelinks.txt | Mantra -s | anew -q $url/js/js_secrets.txt
}

search_patterns(){
        echo "[+] Searchin vulnerable patterns in urls"
        echo "[+]       Searching XSS"
        gf xss $url/scrape/url_extract.txt | anew -q $url/vulns/xss.txt

        echo "[+]       Searching ssrf"
        gf ssrf $url/scrape/url_extract.txt | anew -q $url/vulns/ssrf.txt

        echo "[+]       Searching redirect"
        gf redirect $url/scrape/url_extract.txt | anew -q $url/vulns/redirect.txt
}

hunt_vuln(){
        echo "[+] Hunting reflected XSS"
}

create_folders
harvesting_subdomains
url_scrape
js_analysis
search_patterns