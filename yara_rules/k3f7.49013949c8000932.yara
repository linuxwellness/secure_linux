
rule k3f7_49013949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.49013949c8000932"
     cluster="k3f7.49013949c8000932"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['268a5655d06c1dc12cef3466af074556','2b23d042a2691aa4caa74a636d863e47','ec3ced4fe482a5bdd70b8e796d752387']"

   strings:
      $hex_string = { d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
