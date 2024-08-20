# -*- coding: utf-8 -*-
"""
Created on Fri Jun  9 18:36:01 2023

@author: utilisateur
"""

import re
from stop_words import get_stop_words
from geotext import GeoText
import enchant
d = enchant.Dict("en_US")
import json
import dateutil.parser as dparser
from rake_nltk import Rake
import wikipedia
from sklearnex import patch_sklearn
patch_sklearn()
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.pipeline import Pipeline

incident_types=["phishing", "malware", "DoS", "DDoS", "data leak", "insider attack", "ransomware"]
incident_types=["phishing", "malware", "DoS", "data leak", "insider attack", "ransomware"]
wikipedia_names=["In-session phishing", "Malware", "Denial-of-service attack", "Data breach",'Insider threat', "Ransomware"]
#selected for each best wikipedia page print(wikipedia.search("phishing"))
MonthDict={ 1 : "january",
       2 : "february",
       3 : "march",
       4 : "april",
       5 : "may",
       6 : "june",
       7 : "july",
       8 : "august",
       9 : "september",
       10 : "october",
       11 : "november",
       12 : "december"
}
months=list(MonthDict.values())
f=open("test.txt", "w")

def prepare(sentence, punct=False):
    """
    Parameters
    ----------
    sentence : string
        sentence to clean.
    punct : bool, optional
        shall we remove punctuation also?. The default is False.

    Returns
    -------
    sentence : string
        sentence without capital, without ", ,, 's, without stop words, without too muche spaces, eventually without punctuation.

    """
    sentence=sentence.lower()
    sentence=re.sub("\"|,|\'s", "", sentence) # ",
    stop_words = get_stop_words('en')+["can"]
    sentence=" ".join([(w if w not in stop_words else "") for w in sentence.split(" ")])
    sentence=re.sub(' +', ' ', sentence).strip()
    if punct:
        sentence=re.sub(r'[^\w\s]','',sentence)
    return sentence

def get_train_sentences(wikipedia_names=wikipedia_names):
    """
    Parameters
    ----------
    wikipedia_names : list of strings
        list of string for wikipedia pages name. The default is wikipedia_names, defined earlier

    Returns
    -------
    sentences : list of string
        wikipedia summary.

    """
    sentences=[]
    for page in wikipedia_names:
        summary=wikipedia.summary(page)
        summary_cleaned=prepare(summary, punct=True)
        sentences.append(summary_cleaned)
    return sentences

class Classifier:
    def __init__(self, sentences, targets):
        """

        Parameters
        ----------
        sentences : list of tsring
            training phrases.
        targets : list of strings
            target of incident classifier, shall be incident_types.

        Does
        -------
        fit model to sentences

        """
        self.sentences=sentences
        self.targets=targets
        self.model=self._train()
        
    def _train(self):
        text_clf = Pipeline([('vect', CountVectorizer()),('tfidf', TfidfTransformer()),('clf', MultinomialNB())])
        text_clf = text_clf.fit(self.sentences, self.targets)
        return text_clf
        
    def predict(self, sentence):
        return self.model.predict([sentence])[0]

class Sentences:
        def __init__(self, file:str, output_file:str):
            """

            Parameters
            ----------
            file : str
                input file sentences.txt
            output_file : str
                output json file.
            """
            self.txt=open(file, 'r').read()
            self.output_file=output_file
        
        def write(self):
            """
            write dump result in file

            """
            with open(self.output_file, "w") as of:
                json.dump(self.output, of)
            
        def parse(self):
            """
            There is the work:
            going through each sentence, into each word, 
            to eventually class it into ip, date, locatio, system or user
            finally predicts incident type
            create dict of utput
            """
            self.output=[] #list of result dict
            #for finding each location name in text
            geo = GeoText(self.txt.replace("\n", " "))
            cities=[city.lower() for city in geo.cities]
            countries=[country.lower() for country in geo.countries]
            #get classification model based on wikipedia
            #for incident type
            x=get_train_sentences()
            cl=Classifier(x, incident_types)
            for sentence in self.txt.split("\n"):
                sentence_clean=prepare(sentence) #clean sentence
                # set all to begin
                month, year, day=False, False, False
                incident_type=[]
                ip_address=[]
                location=[]
                system=[]
                user=[]
                time=[]
                for word in sentence_clean.split(" "):
                    if word in " ".join(cities+countries):
                        #location found
                        location.append(word)
                    elif word.count(".")==3:
                         # ip found
                        ip_address.append(word)
                    elif word.count("\/")>1 or (word.count(":")>1 and word.count("-")>1):
                        #time stamp found
                        time.append(dparser.parse(word,fuzzy=True).isoformat())
                    elif word in months:
                        #month found
                        month=months.index(word)+1
                    elif bool(re.search('\d{4}', word)):
                        #year found
                        year=re.search('\d{4}', word).group(0)
                    elif bool(re.search('\d+(st|rd|nd|th)', word)):
                        #day found
                        day=re.search(r'\d+', word).group(0)
                    elif word.count("-")==2 and word.count(":")==2:
                        #timestamp found
                        time.append(dparser.parse(word,fuzzy=True).isoformat())
                    elif word.count("-")==1:
                        #system found
                        system.append(word)
                # let's find the user:
                # rake analyses sentence in order to find grammatical subjects
                rake = Rake()
                rake.extract_keywords_from_text(sentence.replace("\"", ""))
                subject=rake.get_ranked_phrases() #bag of words of sentence subject
                subject_list=" ".join(subject).split(" ")  #recomposed into a signle list
                i=0
                while user==[] and i<len(subject_list): #while user not found
                    #check if word or Word in subject_list does not exists or i not already a system name
                    if not (d.check(subject_list[i]) or d.check(subject_list[i].title()) or subject_list[i] in "".join(system)):
                        user.append(subject_list[i])
                    i+=1
                # if date was not a timestamp, need to recompose day month year found
                if day and month and year:
                    time.append(dparser.parse(str(day)+" "+str(month)+" "+str(year),fuzzy=True).isoformat())
                #classification!!!!!!!!!!!!!
                #replace every ip, user or system name by "ip", "user", "system"
                sentence_replaced=sentence.replace(str(ip_address), "ip").replace(str(system), "system").replace(str(user), "user")
                incident_type.append(cl.predict(sentence_replaced))
                #now we have it all, let's make output dict
                if len(ip_address+time+user+system)>0: # if sentence is a real incident
                    out_dict={
                                "Sentence" : sentence.replace("\"", ""), 
                                "Incident": {
                                    "Type": incident_type,
                                    "Source": {
                                        "IP": ip_address,
                                        "Location": location
                                    },
                                    "Target": {
                                        "System": system,
                                        "User": user
                                    },
                                    "Time": time
                                }
                            }
                    self.output.append(out_dict)

result=Sentences("sentences.txt", "output.json")
result.parse()
result.write()