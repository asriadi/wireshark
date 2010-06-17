<!--
Syntax: xsltproc Values.xsl FIX44.xml
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 <xsl:output  method="text" encoding="UTF-8"/>

 <xsl:template match="text()"/>
 <xsl:template match="/">/* DO NOT EDIT
 * This file is autogenerated
 *
 * $Id$
 *
 */

  <xsl:apply-templates/>

</xsl:template>
 
<!--
translate(@description,$uppercase,$smallcase)  
-->

<xsl:variable name="smallcase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<xsl:template match="fix/fields">
<xsl:for-each select="field[value]">
    <xsl:variable name="val_type"  >
    <xsl:choose>   
           <xsl:when test="@type='STRING'"> string_string </xsl:when>
  	   <xsl:otherwise> value_string </xsl:otherwise>
    </xsl:choose>
    </xsl:variable>
   static const <xsl:copy-of select="$val_type" /> <xsl:value-of select="@name"/>_val[] = { <xsl:for-each select="value"> <xsl:choose>
             <xsl:when test="../@type='INT'">
       { <xsl:value-of select="@enum"/>, "<xsl:value-of select="translate(@description,'_',' ')"/>" },</xsl:when>
             <xsl:when test="../@type='STRING'">
       { "<xsl:value-of select="@enum"/>", "<xsl:value-of select="translate(@description,'_',' ')"/>" },</xsl:when>
  	     <xsl:otherwise>
       { '<xsl:value-of select="@enum"/>', "<xsl:value-of select="translate(@description,'_',' ')"/>" },</xsl:otherwise>
	   </xsl:choose>
	</xsl:for-each>
       { 0, NULL }
   };

</xsl:for-each>
</xsl:template>

<xsl:template match="fix/messages">
   static const string_string messages_val[] = { <xsl:for-each select="message">
       { "<xsl:value-of select="@msgtype"/>", "<xsl:value-of select="@name"/>" }, </xsl:for-each>
       { "", NULL }
   };
</xsl:template>

</xsl:stylesheet>
