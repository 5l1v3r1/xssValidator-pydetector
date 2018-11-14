import os
import SimpleHTTPServer
import SocketServer

from base64 import b64decode
from urllib import unquote

from selenium import webdriver
from selenium.webdriver.remote.errorhandler import UnexpectedAlertPresentException
from selenium.common.exceptions import NoAlertPresentException
from splinter import Browser


PORT = 8094
user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0)"\
    "Gecko/20100101 Firefox/45.1"
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--disable-web-security")
chrome_options.add_argument("--disable-xss-auditor")
browser = Browser('chrome', user_agent=user_agent,
                  headless=False, options=chrome_options)


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write("")

    def do_POST(s):
        content_len = int(s.headers.getheader('content-length', 0))
        post_body = s.rfile.read(content_len)
        if post_body[:13] == "http-response":
            s.send_response(200)
            s.send_header("Content-type", "text/json")
            s.end_headers()
            if probe(post_body):
                s.wfile.write('{"value":1,"msg":"XSS found: prompt(1)",'
                              '"trigger":"299792458"}')
            else:
                s.wfile.write("No XSS found in response")
        else:
            s.send_response(401)
            s.send_header("Content-type", "text/json")
            s.end_headers()


def probe(data):
    # Normalize data
    data = [_.split("=") for _ in data.split("&")]
    http_url = b64decode(unquote(data[1][1]))
    http_headers = b64decode(unquote(data[2][1]))
    http_response = unquote(data[0][1])

    print http_url
    print

    html_response = "var page=atob('%s');page=page.substr(page.indexOf('\\n\\n'), page.length).trim();top.document.write(page);" % http_response
    xssDetection = '''var tags = ["a", "abbr", "acronym", "address", "applet", "area", "article", "aside", "audio", "audioscope", "b", "base", "basefont", "bdi", "bdo", "bgsound", "big", "blackface", "blink", "blockquote", "body", "bq", "br", "button", "canvas", "caption", "center", "cite", "code", "col", "colgroup", "command", "comment", "datalist", "dd", "del", "details", "dfn", "dir", "div", "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "fn", "font", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i", "iframe", "ilayer", "img", "input", "ins", "isindex", "kbd", "keygen", "label", "layer", "legend", "li", "limittext", "link", "listing", "map", "mark", "marquee", "menu", "meta", "meter", "multicol", "nav", "nobr", "noembed", "noframes", "noscript", "nosmartquotes", "object", "ol", "optgroup", "option", "output", "p", "param", "plaintext", "pre", "progress", "q", "rp", "rt", "ruby", "s", "samp", "script", "section", "select", "server", "shadow", "sidebar", "small", "source", "spacer", "span", "strike", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "tt", "u", "ul", "var", "video", "wbr", "xml", "xmp"];
var eventHandler = ["mousemove", "mouseout", "mouseover"];
      tags.forEach(function(tag) {
        currentTags = document.querySelectorAll(tag);
        if (currentTags !== null && currentTags.length > 0) {
          for (i = 0; i < currentTags.length; i++) {
            eventHandler.forEach(function(currentEvent) {
              var ev = document.createEvent("MouseEvents");
              ev.initEvent(currentEvent, true, false);
              currentTags[i].dispatchEvent(ev);
            });
          }
        }
      });'''

    def xss_detected():
        print "XSS found!"

    def verify_xss():
        try:
            prompt = browser.get_alert()
            prompt.accept()
            xss_detected()
            return True
        except UnexpectedAlertPresentException:
            pass#print "UNEXPECTED XSS"
        except NoAlertPresentException:
            pass#print "NO XSS DETECTED"
        except:
            pass
        return False
    # Use dummy page for testing
    browser.visit("about:config")
    #browser.visit(http_url)
    # Load HTML Response onto dummy page
    browser.execute_script(html_response)
    # Did any alerts trigger?
    if verify_xss(): return True
    # Attempt to trigger onmouse events
    browser.execute_script(xssDetection)
    # Did any alerts trigger?
    if verify_xss(): return True
    return False

def main():
    # Start HTTP server
    Handler = ServerHandler
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "Web Server running on port %d\n" % PORT
    httpd.serve_forever()


if __name__ == "__main__":
    main()