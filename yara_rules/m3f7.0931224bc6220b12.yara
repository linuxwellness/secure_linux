
rule m3f7_0931224bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.0931224bc6220b12"
     cluster="m3f7.0931224bc6220b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker trojanclicker"
     md5_hashes="['161c38938960da57e8682c12df76f088','246c633dbd46c6df741d03f36be97425','d9297e9fda5cd673a7f6fb60e2798d8c']"

   strings:
      $hex_string = { 4f75543667413568777a7130716c38756e4151594842326530746258394666694d35543466517468614e4f6a574a6d69317061566c6358643339377341615a72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
