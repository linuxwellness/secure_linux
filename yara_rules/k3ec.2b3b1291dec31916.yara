
rule k3ec_2b3b1291dec31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2b3b1291dec31916"
     cluster="k3ec.2b3b1291dec31916"
     cluster_size="6"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector moctezuma"
     md5_hashes="['349a8af974db2804f77aaf32b9380d6b','5908406d839bede1a6483aec92671e7e','f9f00c5db73457a5513232d36dbb95cf']"

   strings:
      $hex_string = { c4b0f567e4bd7a7801a1ee459b5ec8c547b3ab84487d95a3506fa7fb21ec923d7699bf2fd0499cba4651132c3e7c91262ef308f5fd02d7076c660559e3158ab4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
