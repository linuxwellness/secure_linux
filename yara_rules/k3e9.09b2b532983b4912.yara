
rule k3e9_09b2b532983b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09b2b532983b4912"
     cluster="k3e9.09b2b532983b4912"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['187c79a4d23fe30a1e258da34cd62005','26b688efca1ffcab3b4e2c3b79c42936','f468dcdc5ed5dfc970edd81337429231']"

   strings:
      $hex_string = { ee0d1895097d9edc60a6323de8d80c7d9015814076fef619c60a02b0a439369030a589cb1dba207c94210f0ea2aec2888ee17416558667a8a0ea48a3d41bd042 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
