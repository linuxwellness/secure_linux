
rule k3e9_2234a61bd29a9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2234a61bd29a9912"
     cluster="k3e9.2234a61bd29a9912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="berbew backdoor peed"
     md5_hashes="['147b025352e4f36296e5026dd387ab8a','ae13896a392ce403de15b0bb7fc42d98','da1dd598f088e3f5356bebcb5425b168']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
