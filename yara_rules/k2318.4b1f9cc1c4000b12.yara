
rule k2318_4b1f9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4b1f9cc1c4000b12"
     cluster="k2318.4b1f9cc1c4000b12"
     cluster_size="26"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['07eca445def29cba46be4b0d241d9309','0d68ee5faf7949651ca784e6d1ac001f','931e200172c2bc559e0050b854469e88']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029273b20206d617267696e2d6c6566743a202d35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
