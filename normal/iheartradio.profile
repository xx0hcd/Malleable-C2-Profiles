#iheartradio
#chose a popular top 40 station 'hit-nation'..
#had to cut some things out due to size, especially cookie
#the ouput fields look messy but looks good in wireshark during testing
#xx0hcd

https-certificate {
	set CN 		"iheart.map.fastly.net";
	set C		"US";
	set O		"Fastly Inc.";
	set L		"San Francisco";
	set ST		"California";
	set validity	"365";
}

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/live/hit-nation-4222/";
    
    client {

	header "Host" "www.iheart.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
	
        
        metadata {
            base64url;
            
	    prepend "GED_PLAYLIST_ACTIVITY=";
	    prepend "_gads=ID=53c4a:S=ALNI_M32;";
	    prepend "uid=1492;";
	    prepend "pid=3913;";
	    prepend "ihr_c=US;id=HdqX;";
	    header "Cookie";

        }

    }

    server {

	header "Content-Type" "text/html; charset=utf-8";
	header "Edge-Control" "cache-maxage=3600";
	header "Server" "nginx/1.4.6 (Ubuntu)";
	header "X-Powered-By" "Express";
	header "Access-Control-Allow-Origin" "*";
	header "Accept-Ranges" "bytes";
	header "Via" "1.1 varnish";
	header "Age" "315";
	header "Connection" "close";
	header "X-Served-By" "cache-dfw1822-DFW";
	header "X-Cache" "HIT";
	header "X-Cache-Hits" "1";
	header "X-Timer" "S1499866924.089752,VS0,VE1";
        

        output {

            base64url;

	    prepend "<!DOCTYPE html>
    <html lang='en' xmlns:fb='http://ogp.me/ns/fb'>
    <head>
      <title>Listen to Hit Nation Radio Live - All of Today's Biggest Hits | iHeartRadio</title>
      <meta data-react-helmet='true' charset='utf-8'/><meta data-react-helmet='true' name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no'/><meta data-react-helmet='true' name='mobile-web-app-capable' content='yes'/> <link data-react-helmet='true' rel='shortcut icon' href='/assets/favicon.cf2eff6db48eda72637f3c01d6ce99ae.ico?rev=7.33.1' type='image/ico'/><link data-react-helmet='true' rel='apple-touch-icon' href='/assets/apple-touch-icon.40395b8a92866d7206175b320b251cd3.png?rev=7.33.1'/><link data-react-helmet='true' rel='shortcut icon' href='/assets/apple-touch-icon.40395b8a92866d7206175b320b251cd3.png?rev=7.33.1'/><link data-react-helmet='true' rel='chrome-webstore-item' href='https://chrome.google.com/webstore/detail/iheartradio/djfamdpdfnbdehpafbeefbpobbohmfnc'/><link data-react-helmet='true' rel='manifest' href='/assets/manifest.828b7817d23e2d62cf3d7e797ae0056f.json?rev=7.33.1'/>
      <link rel='alternate' href='android-app://com.clearchannel.iheartradio.controller/ihr/goto/live/4422' data-reactid='2'/><link rel='alternate' href='ios-app://290638154/ihr/goto/live/4422' data-reactid='3'/><link rel='search' type='application/opensearchdescription+xml' title='iHeartRadio' href='/assets/opensearch.bb1705850ffcb01dd81ec10d6e177d1c.xml?rev=7.33.1' data-reactid='4'/><link href='https://plus.google.com/+iHeartRadio' rel='author' data-reactid='5'/><link href='https://plus.google.com/+iHeartRadio' rel='publisher' data-reactid='6'/><link rel='canonical' href='https://www.iheart.com/live/hit-nation-4422/' data-reactid='7'/><link rel='image_src' href='https://iscale.iheart.com/catalog/live/4422' data-reactid='8'/><meta name='thumbnail' content='https://iscale.iheart.com/catalog/live/4422' data-reactid='9'/><meta name='description' content='Listen to Hit Nation Live for Free! Hear All of Today&#x27;s Biggest Hits, only on iHeartRadio.' data-reactid='10'/><meta name='keywords' content='Listen,Live,Hit Nation,Digital,NAT,Music,Talk,Radio,Top 40 &amp; Pop,Online,Streaming,Free,iHeartRadio,iHeart' data-reactid='11'/><meta name='twitter:label1' content='Genre' data-reactid='12'/><meta name='twitter:data1' content='Top 40 &amp; Pop' data-reactid='13'/><meta name='twitter:label2' content='Location' data-reactid='14'/><meta name='twitter:data2' content='DIGITAL-NAT' data-reactid='15'/><meta property='fb:app_id' content='121897277851831' data-reactid='16'/> content='https://iscale.iheart.com/catalog/live/4422' data-reactid='21'/>
      <style class='server-style-loader-element'><href='https://www.iheart.com/live/hit-nation-4422/?autoplayid=";


	    append "<meta property='og:site_name' content='iHeartRadio' data-reactid='22'/><meta property='og:description' content='Listen to Hit Nation Live for Free! Stream Top 40 &amp; Pop songs online from this radio station, only on iHeartRadio.' data-reactid='23'/><meta itemprop='name' content='Listen to Hit Nation Radio Live - All of Today&#x27;s Biggest Hits' data-reactid='24'/><meta  name='twitter:app:name:googleplay' content='iHeartRadio' data-reactid='46'/><meta name='twitter:app:id:googleplay' content='com.clearchannel.iheartradio.controller' data-reactid='47'/><meta property='al:ios:app_store_id' content='290638154' data-reactid='48'/><meta property='al:ios:app_name' content='iHeartRadio' data-reactid='49'/><meta property='al:android:package' content='com.clearchannel.iheartradio.controller' data-reactid='50'/><meta property='al:android:app_name' content='iHeartRadio' data-reactid='51'/>
      <link rel='stylesheet' type='text/css' href='/assets/web-styles.c28d83ef1f71cb7b9282646a7edecdb0.css?rev=7.33.1'></link>
</div></div></div><div id='dialog' data-reactid='103'></div><div id='dialog-secondary' data-reactid='104'></div><div data-reactid='105'><!-- react-empty: 106 --></div><!-- react-empty: 107 --><div data-reactid='108'></div><div data-reactid='109'></div><div class='growls no-growls' data-reactid='110'></div><div class='adblock-bait pub_300x250 pub_300x250m pub_728x90 text-ad textAd text_ad text_ads text-ads text-ad-links' data-reactid='111'></div></div></div>
      <div id='jw-wrapper' class='hidden'>
        <div id='jw-player'></div>
      </div>
      <div id='ads-wrapper' class='hidden'>
        <a id='ads-learn-more' target='_blank'>Learn More</a>
        <div id='ads-player'></div>
      </div>
      <script src=/a/locale/?rel=7.33.1></script>
      <script src=/assets/vendor.a465f0a08a077b19e744.js?rev=7.33.1></script>
      <script src=/assets/web.a465f0a08a077b19e744.js?rev=7.33.1></script>
    </body>
  </html>";

            print;
        }
    }
}

http-post {
    
    set uri "/Live/hit-nation-4222/";
    set verb "GET";

    client {

	header "Host" "www.iheart.com";
	header "Accept" "*/*";     
        
        output {
            base64url;
	    
	    prepend "GED_PLAYLIST_ACTIVITY=";
	    prepend "_gads=ID=53c4a:S=ALNI_M32;";
	    prepend "uid=1492;";
	    prepend "pid=3913;";
	    prepend "ihr_c=US;id=HdqX;";
	    header "Cookie";


        }


        id {
            base64url;

	    parameter "autoplay";

        }
    }

    server {

	header "Content-Type" "text/html; charset=utf-8";
	header "Edge-Control" "cache-maxage=3600";
	header "Server" "nginx/1.4.6 (Ubuntu)";
	header "X-Powered-By" "Express";
	header "Access-Control-Allow-Origin" "*";
	header "Accept-Ranges" "bytes";
	header "Via" "1.1 varnish";
	header "Age" "315";
	header "Connection" "close";
	header "X-Served-By" "cache-dfw1822-DFW";
	header "X-Cache" "HIT";
	header "X-Cache-Hits" "1";
	header "X-Timer" "S1499866924.089752,VS0,VE1";
        
        #just keeping output together for responses
        output {
            base64;

            prepend "<!DOCTYPE html>
    <html lang='en' xmlns:fb='http://ogp.me/ns/fb'>
    <head>
      <title>Listen to Hit Nation Radio Live - All of Today's Biggest Hits | iHeartRadio</title>
      <meta data-react-helmet='true' charset='utf-8'/><meta data-react-helmet='true' name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no'/><meta data-react-helmet='true' name='mobile-web-app-capable' content='yes'/> <link data-react-helmet='true' rel='shortcut icon' href='/assets/favicon.cf2eff6db48eda72637f3c01d6ce99ae.ico?rev=7.33.1' type='image/ico'/><link data-react-helmet='true' rel='apple-touch-icon' href='/assets/apple-touch-icon.40395b8a92866d7206175b320b251cd3.png?rev=7.33.1'/><link data-react-helmet='true' rel='shortcut icon' href='/assets/apple-touch-icon.40395b8a92866d7206175b320b251cd3.png?rev=7.33.1'/><link data-react-helmet='true' rel='chrome-webstore-item' href='https://chrome.google.com/webstore/detail/iheartradio/djfamdpdfnbdehpafbeefbpobbohmfnc'/><link data-react-helmet='true' rel='manifest' href='/assets/manifest.828b7817d23e2d62cf3d7e797ae0056f.json?rev=7.33.1'/>
      <link rel='alternate' href='android-app://com.clearchannel.iheartradio.controller/ihr/goto/live/4422' data-reactid='2'/><link rel='alternate' href='ios-app://290638154/ihr/goto/live/4422' data-reactid='3'/><link rel='search' type='application/opensearchdescription+xml' title='iHeartRadio' href='/assets/opensearch.bb1705850ffcb01dd81ec10d6e177d1c.xml?rev=7.33.1' data-reactid='4'/><link href='https://plus.google.com/+iHeartRadio' rel='author' data-reactid='5'/><link href='https://plus.google.com/+iHeartRadio' rel='publisher' data-reactid='6'/><link rel='canonical' href='https://www.iheart.com/live/hit-nation-4422/' data-reactid='7'/><link rel='image_src' href='https://iscale.iheart.com/catalog/live/4422' data-reactid='8'/><meta name='thumbnail' content='https://iscale.iheart.com/catalog/live/4422' data-reactid='9'/><meta name='description' content='Listen to Hit Nation Live for Free! Hear All of Today&#x27;s Biggest Hits, only on iHeartRadio.' data-reactid='10'/><meta name='keywords' content='Listen,Live,Hit Nation,Digital,NAT,Music,Talk,Radio,Top 40 &amp; Pop,Online,Streaming,Free,iHeartRadio,iHeart' data-reactid='11'/><meta name='twitter:label1' content='Genre' data-reactid='12'/><meta name='twitter:data1' content='Top 40 &amp; Pop' data-reactid='13'/><meta name='twitter:label2' content='Location' data-reactid='14'/><meta name='twitter:data2' content='DIGITAL-NAT' data-reactid='15'/><meta property='fb:app_id' content='121897277851831' data-reactid='16'/> content='https://iscale.iheart.com/catalog/live/4422' data-reactid='21'/>
      <style class='server-style-loader-element'><href='https://www.iheart.com/live/hit-nation-4422/?autoplayid=";


	    append "<meta property='og:site_name' content='iHeartRadio' data-reactid='22'/><meta property='og:description' content='Listen to Hit Nation Live for Free! Stream Top 40 &amp; Pop songs online from this radio station, only on iHeartRadio.' data-reactid='23'/><meta itemprop='name' content='Listen to Hit Nation Radio Live - All of Today&#x27;s Biggest Hits' data-reactid='24'/><meta  name='twitter:app:name:googleplay' content='iHeartRadio' data-reactid='46'/><meta name='twitter:app:id:googleplay' content='com.clearchannel.iheartradio.controller' data-reactid='47'/><meta property='al:ios:app_store_id' content='290638154' data-reactid='48'/><meta property='al:ios:app_name' content='iHeartRadio' data-reactid='49'/><meta property='al:android:package' content='com.clearchannel.iheartradio.controller' data-reactid='50'/><meta property='al:android:app_name' content='iHeartRadio' data-reactid='51'/>
      <link rel='stylesheet' type='text/css' href='/assets/web-styles.c28d83ef1f71cb7b9282646a7edecdb0.css?rev=7.33.1'></link>
</div></div></div><div id='dialog' data-reactid='103'></div><div id='dialog-secondary' data-reactid='104'></div><div data-reactid='105'><!-- react-empty: 106 --></div><!-- react-empty: 107 --><div data-reactid='108'></div><div data-reactid='109'></div><div class='growls no-growls' data-reactid='110'></div><div class='adblock-bait pub_300x250 pub_300x250m pub_728x90 text-ad textAd text_ad text_ads text-ads text-ad-links' data-reactid='111'></div></div></div>
      <div id='jw-wrapper' class='hidden'>
        <div id='jw-player'></div>
      </div>
      <div id='ads-wrapper' class='hidden'>
        <a id='ads-learn-more' target='_blank'>Learn More</a>
        <div id='ads-player'></div>
      </div>
      <script src=/a/locale/?rel=7.33.1></script>
      <script src=/assets/vendor.a465f0a08a077b19e744.js?rev=7.33.1></script>
      <script src=/assets/web.a465f0a08a077b19e744.js?rev=7.33.1></script>
    </body>
  </html>";

            print;
        }
    }
}

http-stager {
    server {
        header "Server" "nginx/1.4.6 (Ubuntu)";
        header "Content-Type" "text/html; charset=utf-8";
        header "Connection" "close";
    
    }


}

stage {
	#random compile time
	set compile_time "02 Jul 2017 05:32:16";
	set userwx "false";
}
