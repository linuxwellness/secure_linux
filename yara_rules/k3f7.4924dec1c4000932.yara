
rule k3f7_4924dec1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4924dec1c4000932"
     cluster="k3f7.4924dec1c4000932"
     cluster_size="62"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script redirector html"
     md5_hashes="['04bb078dbcb6b002e0e0be9ede22b8f5','06a057da64cc79cc2b4b652bdf28520f','4b7eb3d434d017d43cec1178d4aa599e']"

   strings:
      $hex_string = { d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
