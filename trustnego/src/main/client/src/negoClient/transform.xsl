<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"
	xmlns:cl="http://localhost:8080/claim" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
	xmlns:sp="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy"> <!-- exclude-result-prefixes="x" -->
	<xsl:output method="xml" indent="yes" />
	
	<xsl:variable name="idcred" select="'id_cred'" />
	<xsl:variable name="minor" select="'&lt;'"></xsl:variable>
	
	


	<xsl:template match="/">
	
	

		
	<xsl:variable name="x509_childs">
   <xsl:value-of select="count(descendant::sp:X509Token)"/>
  	</xsl:variable>
  	<xsl:variable name="wstClaim_childs">
   <xsl:value-of select="count(descendant::wst:Claims)"/>
  	</xsl:variable>

			
			
				<xsl:for-each select="wsp:Policy">
				
				<package name="negoClient" xmlns="http://drools.org/drools-5.2"
						xmlns:xs="http://www.w3.org/2001/XMLSchema-instance">
						<import name="edu.uiuc.cs.TrustBuilder2.messages.X509CredentialBrick" />
						<rule name="policy">
						<lhs>
				
					<xsl:for-each select="wsp:ExactlyOne/wsp:All/sp:X509Token">
					
						<pattern>
						<xsl:attribute name="identifier">
						<xsl:value-of select="$idcred"/>
						<xsl:value-of select='position()' />
						</xsl:attribute>
						<xsl:attribute name="object-type">X509CredentialBrick</xsl:attribute>
						<expr>
						<xsl:for-each select="sp:IssuerName">
						getIssuer() == "<xsl:value-of select="normalize-space(../sp:IssuerName)"/>" <xsl:if test = "position() != count(../*)">&amp;&amp; </xsl:if><!-- <xsl:if test="$wstClaim_childs > 0"> &amp;&amp; </xsl:if> -->
						
						</xsl:for-each>
						
						
						
						<xsl:for-each select="wst:Claims">
							<xsl:for-each select="cl:Claim">
							getFields().get("<xsl:value-of select="cl:Attribute"></xsl:value-of>")
							<xsl:if test="cl:Op = 'EQ'">== </xsl:if>
							<xsl:if test="cl:Op = 'GT'">></xsl:if>
							<xsl:if test="cl:Op = 'LT'"><xsl:value-of select="$minor"/></xsl:if>
							<xsl:if test="cl:Op = 'GTEQ'">>=</xsl:if>
							<xsl:if test="cl:Op = 'LTEQ'"><xsl:value-of select="$minor"/>=</xsl:if>
							&quot;<xsl:value-of select="cl:Value"></xsl:value-of>&quot;<xsl:if test="position() != count(../*)"> &amp;&amp; </xsl:if>
							
							
						
						
						<xsl:for-each select="../cl:Ownership">
						isOwnershipVerified() == <xsl:value-of select="@Status"></xsl:value-of><xsl:if test="(position()+1) &lt;  $wstClaim_childs"> &amp;&amp; </xsl:if>
						
						</xsl:for-each>
						</xsl:for-each>
						</xsl:for-each>
						
						</expr>
						</pattern>
					
					</xsl:for-each>
				<pattern identifier="credList" object-type="java.util.ArrayList" >
				</pattern>
				</lhs>
				
				<xsl:call-template name="rhs"/>
				
				

			</rule>
			</package>
				</xsl:for-each>
				

	</xsl:template>
	
	<xsl:template name="rhs" >
		<rhs>

			<xsl:for-each select="/wsp:Policy/wsp:ExactlyOne/wsp:All/sp:X509Token">
			credList.add(id_cred<xsl:value-of select='position()' />);
			</xsl:for-each>

		
		</rhs>
	</xsl:template>
	
</xsl:stylesheet>