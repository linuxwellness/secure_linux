
rule n3ed_15f2d29d86220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f2d29d86220912"
     cluster="n3ed.15f2d29d86220912"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['310c9600b655684ed565171324f1f779','402982bdd76f366b22069381fbba19ce','d399d6b71a3adf91ccc7a13f8236ac3f']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e80136000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
