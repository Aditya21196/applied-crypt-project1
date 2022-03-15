"""
The dictionaries for testing
"""

# dict 1
_text_1 = "underwaists wayfarings fluty analgia refuels transcribing nibbled okra buttonholer venalness hamlet praus apprisers presifted cubital walloper dissembler bunting wizardries squirrel preselect befitted licensee encumbrances proliferations tinkerer egrets recourse churl kolinskies ionospheric docents unnatural scuffler muches petulant acorns subconscious xyster tunelessly boners slag amazement intercapillary manse unsay embezzle stuccoer dissembles batwing valediction iceboxes ketchups phonily con"

_text_2 = "rhomb subrents brasiers render avg tote lesbian dibbers jeopardy struggling urogram furrowed hydrargyrum advertizing cheroots goons congratulation assaulters ictuses indurates wingovers relishes briskly livelihoods inflatable serialized lockboxes cowers holster conciliating parentage yowing restores conformities marted barrettes graphically overdevelop sublimely chokey chinches abstracts rights hockshops bourgeoisie coalition translucent fiascoes panzer mucus capacitated stereotyper omahas produ"

_text_3 = "yorkers peccaries agenda beshrews outboxing biding herons liturgies nonconciliatory elliptical confidants concealable teacups chairmanning proems ecclesiastically shafting nonpossessively doughboy inclusion linden zebroid parabolic misadventures fanciers grovelers requiters catmints hyped necklace rootstock rigorously indissolubility universally burrowers underproduced disillusionment wrestling yellowbellied sherpa unburnt jewelry grange dicker overheats daphnia arteriosclerotic landsat jongleur"

_text_4 = "cygnets chatterers pauline passive expounders cordwains caravel antidisestablishmentarianism syllabubs purled hangdogs clonic murmurers admirable subdialects lockjaws unpatentable jagging negotiated impersonates mammons chumminess semi pinner comprised managership conus turned netherlands temporariness languishers aerate sadists chemistry migraine froggiest sounding rapidly shelving maligning shriek faeries misogynist clarities oversight doylies remodeler tauruses prostrated frugging comestible "

_text_5 = "ovulatory geriatric hijack nonintoxicants prophylactic nonprotective skyhook warehouser paganized brigading european sassier antipasti tallyho warmer portables selling scheming amirate flanker photosensitizer multistage utile paralyzes indexer backrests tarmac doles siphoned casavas mudslinging nonverbal weevil arbitral painted vespertine plexiglass tanker seaworthiness uninterested anathematizing conduces terbiums wheelbarrow kabalas stagnation briskets counterclockwise hearthsides spuriously s"

_dict_1 = [_text_1, _text_2, _text_3, _text_4, _text_5 ]


def get_dictionary_1():
    """
    returns an list of all the dictionary 1 plaintexts
    """
    return _dict_1


# dict 2
_dict_2 = ["lacrosses"
            ,"protectional"
            ,"blistered"
            ,"leaseback"
            ,"assurers"
            ,"frizzlers"
            ,"submerse"
            ,"rankness"
            ,"moonset"
            ,"farcer"
            ,"brickyard"
            ,"stolonic"
            ,"trimmings"
            ,"glottic"
            ,"rotates"
            ,"twirlier"
            ,"stuffer"
            ,"publishable"
            ,"invalided"
            ,"harshens"
            ,"tortoni"
            ,"unlikely"
            ,"alefs"
            ,"gladding"
            ,"favouring"
            ,"particulate"
            ,"baldpates"
            ,"changeover"
            ,"lingua"
            ,"proctological"
            ,"freaking"
            ,"outflanked"
            ,"amulets"
            ,"imagist"
            ,"hyped"
            ,"pilfers"
            ,"overachiever"
            ,"clarence"
            ,"outdates"
            ,"smeltery"]


def get_dictionary_2():
    """
    returns a list of all the words in dictionary 2
    """
    return _dict_2


def make_random_dictionary_2_plaintext(seed = None):
    """
    randomly generated 500 character plaintext from dict 2 words
    """
    import random
    words = get_dictionary_2()
    random.seed(seed)
    word_count = len(words)
    message = ""

    while len(message) < 500:
        if len(message) != 0:
            message += " "
        choice = random.randint(0, word_count-1)
        message += words[choice]

    return message[:500]


def main():
    """
    Main Function
    """
    print("\nDictionary 1")
    dict_1 = get_dictionary_1()
    for i, entry in enumerate(dict_1):
        print(f"Text {i+1} length: {len(entry)} characters\n'{entry}'\n")

    print("\nDictionary 2:")
    dict_2 = get_dictionary_2()
    for entry in dict_2:
        print(entry)

    # with seed
    random_text = make_random_dictionary_2_plaintext(100)
    print(f"\nrandom text (with seed) - text length: {len(random_text)}\n{random_text}")

    # without seed
    random_text_2 = make_random_dictionary_2_plaintext()
    print(f"\nrandom text 2 (no seed) - text length: {len(random_text_2)}\n{random_text_2}")


if __name__ == "__main__":
    main()
