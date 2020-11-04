#used with train.json and classify.json for sorting web URLs to classify them as malicious
#!/usr/bin/python2
import json, sys, getopt, os
def usage():
  print("Usage: %s --file=[filename]" % sys.argv[0])
  sys.exit()
def main(argv):
  ports = ["80", "443"]
  file=''
  goodUrl = malUrl = flag = goodGuess = badGuess = goods = mals = 0
  pair = ""
  myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
  for o, a in myopts:
    if o in ('-f, --file'):
      file=a
    else:
      usage()
  if len(file) == 0:
    usage()
  corpus = open(file)
  f = open("out.py", "w")
  urldata = json.load(corpus, encoding="latin1")
  for record in urldata:
    flag = 0
    # Do something with the URL record data...
    #print (record["url"])
    if int(record["domain_age_days"]) <= 365:
      flag += 2
    if (record["port"] != record["default_port"] and record["port"] not in ports):
      flag += 1
    if record["alexa_rank"] == None:
      flag += 2
    if record["query"] == "":
      flag += 1
    if record["file_extension"] == "exe":
      flag += 1
    if record["num_domain_tokens"] == 3 or record["num_domain_tokens"] == 4:
      flag -= 1
    if record["num_domain_tokens"] == 2 or record["num_domain_tokens"] == 5:
      flag += 1

    if record["malicious_url"] == 1:
      mals += 1
      #print["malicious"]
      if flag >= 3:
        goodGuess += 1
        #print("Correct Guess")
      else:
        badGuess += 1
        #print("Wrong Guess")
    elif record["malicious_url"] == 0:
      goods += 1
      #print("not malicious")
      if flag >= 3:
        badGuess += 1
        #print("Wring Guess")
      else:
        goodGuess += 1
        #print("Correct Guess")

    if flag >= 3:
      #print("1")
      malUrl += 1
    else:
      #print("0")
      goodUrl += 1

    pair += record["url"]
    if flag >= 3:
      pair += " 1"
    else:
      pair += " 0"
    pair += "\n"
    f.write(pair)

  print("good guesses: %d" % (goodGuess))
  print("bad guesses: %d" % (badGuess))

  corpus.close()
  f.close()

if __name__ == "__main__":
  main(sys.argv[1:])
