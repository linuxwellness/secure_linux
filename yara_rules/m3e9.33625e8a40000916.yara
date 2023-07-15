
rule m3e9_33625e8a40000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33625e8a40000916"
     cluster="m3e9.33625e8a40000916"
     cluster_size="172"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore advml click"
     md5_hashes="['031bf1a9fbc5185be7f22cba98245e18','03cac3fe478756155e5aa303967efe6b','1cdf5c298f18beb388de6a4c7c734307']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
