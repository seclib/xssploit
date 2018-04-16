<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/">

    <HTML>

    <HEAD>
      <TITLE>Xssploit report</TITLE>
    </HEAD>
    <BODY BGCOLOR="#FFFFFF">
      <h2>Xssploit report</h2>
      <p>
	  <div align="left">
		<h3 id="top">Resume</h3>
		<table border="1">
		<tr>
			<td>Date</td>
			<td><xsl:value-of select="/XSSploitScan/@date"/></td>
		</tr>
		<tr>
			<td>Scan duration</td>
			<td><xsl:value-of select="/XSSploitScan/@duration"/> seconds</td>
		</tr>
		<tr>
			<td><a href="#pages">Urls scanned</a></td>
			<td><xsl:value-of select="count(/XSSploitScan/Urls/URL)"/></td>
		</tr>
		<tr>
			<td><a href="#forms">forms found</a></td>
			<td><xsl:value-of select="count(/XSSploitScan/forms/form)"/></td>
		</tr>
		<xsl:if test="count(/XSSploitScan/forms/form)>0">
			<tr>
				<td><a href="#xss">XSS found</a></td>
				<td><xsl:value-of select="count(/XSSploitScan/xss)"/></td>
			</tr>
		</xsl:if>
		</table>
	  </div>
	<hr/>
	<h3 id="pages">Pages scanned : </h3>
	<xsl:for-each select="/XSSploitScan/Urls/URL">
	  <a><xsl:attribute name="href">
       <xsl:value-of select="@value"/></xsl:attribute> 
       <xsl:value-of select="@value"/> 
       </a>
      <br/>
	</xsl:for-each>
	  <a href="#top">Top</a>
      </p>
      <hr/>
      <p>
	<h3 id="forms">Forms found : </h3>
	<xsl:for-each select="/XSSploitScan/forms/form">
	  <b>URL : </b><xsl:value-of select="@url"/><br/>
	  <b>Method : </b><xsl:value-of select="@method"/><br/>
	  <b>Parameters : </b><br/>
	    <xsl:for-each select="./parameter">
	      <xsl:value-of select="@name"/> = 
	      <xsl:value-of select="@value"/><br/>
	    </xsl:for-each>
	<br/>
	</xsl:for-each>
	  <a href="#top">Top</a>
      </p>
      <hr/>
      <p>
	<h3 id="xss">XSS found : </h3>
	<xsl:for-each select="/XSSploitScan/xss">
	  <p>
	  <table border="1">
		<tr>
			<td><b>Type</b></td>
			<td><xsl:value-of select="@type"/></td>
		</tr>
		<tr>
			<td><b>URL</b></td>
			<td><xsl:value-of select="@url"/></td>
		</tr>
		<tr>
			<td><b>Method</b></td>
			<td><xsl:value-of select="@method"/></td>
		</tr>
		<tr>
			<td><b>Vulnerable parameter name</b></td>
			<td><xsl:value-of select="@VulnerableParameter"/></td>
		</tr>
		<tr>
			<td><b>Other parameters to pass</b></td>
		</tr>
			<xsl:for-each select="./parameter">
			<tr>
				<td></td>
				<td><xsl:value-of select="@name"/>=<xsl:value-of select="@name"/></td>
			</tr>
			</xsl:for-each>
		<tr>
			<td><b>Unauthorized characters</b></td>
		</tr>
			<xsl:for-each select="./BadChar">
			<tr>
				<td></td>
				<td><xsl:value-of select="text()"/></td>
			</tr>
			</xsl:for-each>
		<tr>
			<td><b>Context</b></td>
			<xsl:for-each select="./Context">
					<td><xsl:value-of select="text()"/></td>
			</xsl:for-each>
		</tr>
	  </table>
	  </p>
	</xsl:for-each>
	   <a href="#top">Top</a>
      </p>
    </BODY>

    </HTML>

  </xsl:template >

</xsl:stylesheet>