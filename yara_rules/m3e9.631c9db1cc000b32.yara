
rule m3e9_631c9db1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c9db1cc000b32"
     cluster="m3e9.631c9db1cc000b32"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['04da6ca007af8beb1837578a925b8f6c','1235e3cfe1d70331285b65c6cd383e25','b1da81709e2b52b22d3c6c77762ad14a']"

   strings:
      $hex_string = { 55e83661f3a98b57130d417894ddaaa51c634c5055762be70176187949aca05480afcdc51a4938702b2af520b259e1d16888ef56324be5b512455549e33eb706 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
