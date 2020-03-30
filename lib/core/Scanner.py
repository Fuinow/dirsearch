# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import re
from difflib import SequenceMatcher

from lib.utils import RandomUtils
from thirdparty.sqlmap import DynamicContentParser


class ScannerException(Exception):
    pass


class Scanner(object):
    def __init__(self, requester, testPath=None, suffix=None):
        if testPath is None or testPath is "":
            self.testPath = ['.env', 'etc/passwd', '.git', 'admin', '.htaccess']
        else:
            self.testPath = testPath

        self.suffix = suffix if suffix is not None else ""
        self.requester = requester
        self.tester = None
        self.redirectRegExp = []
        self.invalidStatus = []
        self.dynamicParser = []
        self.ratio = 0.98
        self.redirectStatusCodes = [301, 302, 307]
        self.setup()

    def setup(self):
        for path in self.testPath:
            firstPath = RandomUtils.randString() + '/' + path + self.suffix
            firstResponse = self.requester.request(firstPath)
            if firstResponse.status not in self.invalidStatus:
                self.invalidStatus.append(firstResponse.status)

            if firstResponse.status == 404:
                # Using the response status code is enough :-}
                continue

            # look for redirects
            secondPath = RandomUtils.randString() + '/' + path + self.suffix
            secondResponse = self.requester.request(secondPath)

            if firstResponse.status in self.redirectStatusCodes and firstResponse.redirect and secondResponse.redirect:
                self.redirectRegExp.append(self.generateRedirectRegExp(firstResponse.redirect, secondResponse.redirect))

            # Analyze response bodies
            dynamicParser = DynamicContentParser(self.requester, firstPath, firstResponse.body, secondResponse.body)

            baseRatio = float("{0:.2f}".format(dynamicParser.comparisonRatio))  # Rounding to 2 decimals

            ratio = self.ratio
            # If response length is small, adjust ratio
            if len(firstResponse) < 2000:
                baseRatio -= 0.1

            if baseRatio < self.ratio:
                ratio = baseRatio
            
            if self.dynamicParser:
                flag = 0
                for  _dynamicParser,__ in  self.dynamicParser:
                    _ratio = dynamicParser.compareTo(_dynamicParser.cleanPage)
                    flag +=  _ratio > ratio
                
                if not flag:
                    self.dynamicParser.append((dynamicParser, ratio))

            else:
                self.dynamicParser.append((dynamicParser, ratio))

    def generateRedirectRegExp(self, firstLocation, secondLocation):
        if firstLocation is None or secondLocation is None:
            return None

        sm = SequenceMatcher(None, firstLocation, secondLocation)
        marks = []

        for blocks in sm.get_matching_blocks():
            i = blocks[0]
            n = blocks[2]
            # empty block

            if n == 0:
                continue

            mark = firstLocation[i:i + n]
            marks.append(mark)

        regexp = "^.*{0}.*$".format(".*".join(map(re.escape, marks)))
        return regexp

    def scan(self, path, response):
        if 404 in self.invalidStatus and response.status == 404:
            return False

        if response.status not in self.invalidStatus:
            return True

        redirectToInvalid = False

        if self.redirectRegExp is not None and response.redirect is not None:
            flag = False
            for redirectRegExp in self.redirectRegExp:
                redirectToInvalid = re.match(redirectRegExp, response.redirect) is not None
                # If redirection doesn't match the rule, mark as found
                flag += redirectToInvalid
            if not redirectToInvalid:
                return True

        for dynamicParser, ratioStandard in self.dynamicParser:
            ratio = dynamicParser.compareTo(response.body)
            if ratio >= ratioStandard:
                return False

            elif redirectToInvalid and ratio >= (ratioStandard - 0.15):
                return False

        return True
