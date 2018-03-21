import os
import json
from statistics import mean


process = 1 # 1 : Arbre ordonné selon la taille et récupération des bids
            # 2 : Arbre bid ordonné selon la nouvelle règle des poids
            # 3 : Arbre avec bid et non ordonné
            # autre : Segment présent dans l'arbre

def load_file():
    with open(r"C:\Users\amarcade\Documents\Récupération_Caping_APB_Reta\Retargeting_APB_trees\SFR_mobile_03-13.txt", 'r') as files:
        line = files.readlines()
        return line

def load_tree(ordered_tree=0): # sépare le fichier règles, leaf_name & bid sous forme liste[(key,value)]

    if ordered_tree == 0:
        with open(r"C:\Users\amarcade\Documents\Récupération_Caping_APB_Reta\Tree_Recommerce_max_ordered_2018_03_16", 'r') as arbre :
            line = arbre.readlines()
    else :
        line = ordered_tree

    regles = []
    key_regle = 1
    leaf_name=[]
    key_leaf_name = 1
    liste_bid = []
    key_bid = 1

    lines2 = [i.split('\n',1)[0] for i in line]
    for line in lines2:
        if line[1:3] == 'le':
            leaf_name.append((key_leaf_name,line))
            key_leaf_name +=1
        elif line[1:3] == 'va':
            liste_bid.append((key_bid,line))
            key_bid+=1
        elif line.find('no_bid') != -1:
            liste_bid.append((key_bid,'\tvalue: no_bid'))
            continue

        elif line != '':
             # condition pour eviter le problème des sauts de lignes
            regles.append((key_regle,line))
            key_regle+=1

    print ("\n===========Chargement de l'arbre OK !============= \n")
    print("liste_regle\n", regles[0:5])
    print("liste_bid : ", liste_bid[0:5])
    return regles,leaf_name,liste_bid

def load_json():
    with open(r"C:\Users\amarcade\Documents\Récupération_Caping_APB_Reta\Bid_Matrix\Recommerce\bid_Matrix_2018_03_06.json") as bid_matrix:
        data = json.load(bid_matrix)
    print("\n===========Chargement de la bid matrix OK !============= \n")
    return data

def load_json_segment_recence():
    with open(r"C:\Users\amarcade\Documents\Récupération_Caping_APB_Reta\Poids_segments_recence\segment_recence_eurobet.json") as segment_recence:
        data = json.load(segment_recence)
    print("\n===========Chargement (segment_recence) OK !============= \n")
    return data

# bid_matrix : fichier json de bid matrix obtenu par load_json
# segment_recence : fichier json frequence et recence
def order_tree_weight(tree_load,bid_matrix,segment_recence,function=sum):
    print("\nSTEP 1 ========== ORDONNANCE DE L'ARBRE avec poids (segment,recence) ===========\n'")
    print("\nfrom order_tree_weight :  (Ordonnance de l'arbre)\n ")
    regles,leaf_name,liste_bid = tree_load
    D_regle= {}
    Schema_Final = []
    fusion_liste = []
    new_arbre= []
    for regle in regles:
        if regle[1] not in D_regle.keys():
            D_regle[regle[1]] = regle[0]

    regle_sans_Doublon = [(k,v) for v,k in D_regle.items()] # regle_sans_Doublon : [(key,règle)]
    print("\nfrom order_tree_weight  : step 1 (Eliminer les règles en double) : \n", regle_sans_Doublon[0:5])
    # calcul du poids

    segment_recence = load_json_segment_recence()
    segment_recence_finale = calcul_weight(tree_load,bid_matrix,segment_recence,function) # segment_recence_finale : [(key_règle, poids),....]
    print("\nfrom order_tree_weight  : step 2 (Calcul du poids) : \n", segment_recence_finale[0:5])
    for elem in regle_sans_Doublon:
        k,v = elem
        for segment_recence in segment_recence_finale:
            k1,poids = segment_recence
            if k == k1:
                Schema_Final.append((elem,poids))
    Tri_regle = sorted(Schema_Final, key=lambda x: x[1])
    Tri_regle.reverse() # pour trier selon le poids décroissant
    print("\nfrom order_tree_weight  : step 3 (Effectuer le tri  des règles par poids decroissant) : \n", Tri_regle[0:5])

    for elem in Tri_regle:
        (k,v) = elem[0]
        if v.find('else') != -1 :
            bid = '\tvalue: no_bid'
            v_else,bid_else = (v,bid)
        else :

            for t in leaf_name:
                if k == t[0]:
                    leaf = t[1]
            for t in liste_bid:
                if k == t[0]:
                    bid = t[1]
            fusion_liste.append(list((v,leaf,bid))) # on enlève les keys
    fusion_liste.append(list((v_else,bid_else))) # on ajoute en dernier le else

    for liste in fusion_liste:
        for elem in liste:
            new_arbre.append(elem+'\n')

    print("\nfrom order_tree_weight  : step 4 (Initialisation de l'arbre par if) : \n")
    # On initialise la première règle avec un if
    if new_arbre[0][0:2] != 'if':
        new_arbre[0] = new_arbre[0].replace('elif','if')

    # on regarde la position de l'ancien if dans l'arbre
    pos = 0
    for elem in new_arbre:
        if elem.find('if') == 0:
            if pos != 0:
                print("Position de l'ancien if : ",(pos/3))
                print("Règle : " ,elem)
        pos+=1
    # On remplace le if de l'ancien arbre par elif
    print("\nfrom order_tree_weight  : step 5 (Transformer l'ancien if en elif) : \n")
    pos = 0
    for elem in new_arbre:
        if elem.find('if') == 0:
            if pos != 0:
                print(pos)
                new_arbre[pos] = new_arbre[pos].replace('if','elif')
                print(elem)
                print(new_arbre[pos])
        pos+=1
    print("\nfrom order_tree_weight  : step 6 (Ordonnance de l'arbre OK !) : \n" ,new_arbre[0:5])

    return new_arbre


# Prend un fichier charger par load_tree()
def order_tree(tree_load):
    print("\nSTEP 1 ========== ORDONNANCE DE L'ARBRE ===========\n'")
    print("\nfrom order_tree :  (Ordonnance de l'arbre)\n ")
    regles,leaf_name,liste_bid = tree_load
    D_regle= {}
    Schema_Final = []
    fusion_liste = []
    new_arbre= []
    for regle in regles:
        if regle[1] not in D_regle.keys():
            D_regle[regle[1]] = regle[0]

    regle_sans_Doublon = [(k,v) for v,k in D_regle.items()]

    print("\nfrom order_tree  : step 1 (Eliminer les règles en double) : \n", regle_sans_Doublon[0:5])
    for elem in regle_sans_Doublon:
        poids = len(elem[1].split(',')) # on associe un poids = taille pour chaque règle
        Schema_Final.append((elem,poids))

    print("\nfrom order_tree  : step 2 (Poids des règles selon la longueur) : \n", Schema_Final[0:5])
    Tri_regle = sorted(Schema_Final, key=lambda x: x[1])
    Tri_regle.reverse() # pour trier selon le poids décroissant

    # règle else de longueur 1 peut être ordonnée au dessus les règles de poids 1

    print("\nfrom order_tree  : step 3 (Effectuer le tri des règles par décroissance) : \n", Tri_regle[0:5])
    for elem in Tri_regle:
        (k,v) = elem[0]
        if v.find('else') != -1 :
            bid = '\tvalue: no_bid'
            v_else,bid_else = (v,bid)
        else :

            for t in leaf_name:
                if k == t[0]:
                    leaf = t[1]
            for t in liste_bid:
                if k == t[0]:
                    bid = t[1]
            fusion_liste.append(list((v,leaf,bid))) # on enlève les keys
    fusion_liste.append(list((v_else,bid_else))) # on ajoute en dernier le else

    for liste in fusion_liste:
        for elem in liste:
            new_arbre.append(elem+'\n')

    print("\nfrom order_tree  : step 4 (Initialisation de l'arbre par if) : \n")
    # On initialise la première règle avec un if
    if new_arbre[0][0:2] != 'if':
        new_arbre[0] = new_arbre[0].replace('elif','if')

    # on regarde la position de l'ancien if dans l'arbre
    pos = 0
    for elem in new_arbre:
        if elem.find('if') == 0:
            if pos != 0:
                print("Position de l'ancien if : ",pos)
                print("Règle : " ,elem)
        pos+=1
    # On remplace le if de l'ancien arbre par elif
    print("\nfrom order_tree  : step 5 (Transformer l'ancien if en elif) : \n")
    pos = 0
    for elem in new_arbre:
        if elem.find('if') == 0:
            if pos != 0:
                print(pos)
                new_arbre[pos] = new_arbre[pos].replace('if','elif')
                print(elem)
                print(new_arbre[pos])
        pos+=1
    print("\nfrom order_tree  : step 6 (Ordonnance de l'arbre OK !) : \n" ,new_arbre[0:5])
    return new_arbre

# new_tree : un fichier txt
# permet de contrôler la structure de l'arbre pour chaque grosse opération --> Ordonnance de l'arbre & implémentation des nouveaux bids
def new_tree_validation(new_tree):
    pos = 0
    liste_pos = []
    validation = False
    print("\nfrom new_tree_validation : ===== (validation de l'arbre) =====\n ")
    for elem in new_tree:
        if elem[0:2] == 'if':
            liste_pos.append(pos)
            print('la position du if :{} '.format(pos))
            print('La règle associée : \n'+elem)
        pos+=1
    if len(liste_pos) == 1 and liste_pos[0] == 0 : # test si le if est unique et est en première positon de l'arbre
        print("\nfrom new_tree_validation : ============= Test du if OK ! ===============\n")
        if str(new_tree[len(new_tree)-2:len(new_tree)-1]).find('else') != -1 and str(new_tree[len(new_tree)-1:]).find('no_bid') != -1:

            print("\nfrom new_tree_validation : ============= Test du else : no_bid OK ! ===============\n")
            validation = True
        elif str(new_tree[len(new_tree)-2:len(new_tree)-1]).find('else') == -1 :
            print("\nfrom new_tree_validation : ============= Test du else : no_bid ECHEC ! ===============\n")
            print(new_tree)
            for elem in new_tree:
                if elem[0:4] == 'else':
                    print('la position du else :{} '.format(pos))
                    print('La règle associée : \n'+elem)
                    pos =+1
            print("from new_tree_validation : ============= Arbre Non Valide ===============")
            validation = False
    else :
        print("\nfrom new_tree_validation : ============= Test du if ECHEC ! ===============\n")
        for pos in liste_pos:
            print("Règle n°{} :\n {}".format(pos,new_tree[pos]))
        validation = False
    return validation

def get_bid(bid_matrix, segment, recence):
    if bid_matrix is None:
        return "1"
    for m in bid_matrix:
        if str(segment) == m["segment"] and str(recence) == m["recence"]:
            return m["bid_value"]
    return "1"
    #raise Exception("No bid found for %s %s" %(segment, recence))


# segment_recence : fichier json obtenu par load_json_segment_recence
def get_segment_recence(segment_recence,segment,recence):
    if segment_recence is None:
        return "1"
    for m in segment_recence:
        if str(segment) == m["segment"] and str(recence) == m["recence"]:
            return m["poids"]
    return "1"


# t est une liste de condition t = ['if every segment[4241077].age < 10080 ', 'segment[4241064].age < 10080 ', 'segment[4241059].age < 10080 ', 'segment[4241022].age < 10080 '...]
def cond_to_segment(t):
    condition = []
    for cond in t:
        if cond[0:2] == 'if':
            condition.append(cond[9:])
        elif cond[0:2] == 'el':
            condition.append(cond[11:])
        else:
            condition.append(cond)
    return condition

def supression(lettre,chaine):
    r = ''
    for c in chaine:
        if c != lettre:
            r = r+c
    return r


# Préparer les data pour utiliser get_bid. # prend en parametre l'arbre chargé
def prepare_data_to_get_bid(load_tree,json_file):

    liste_regle,liste_leaf_name,liste_bid = load_tree
    liste_condition = []
    liste_cond = []
    liste_tuple = []
    liste_tuple_finale = []
    sids = json_file["sids"]
    length = len(sids[0]) # On récupère la taille d'un segment
    i=1

    for k,regle in liste_regle:
        liste_condition.append(regle.split(','))
    print('\nfrom prepare_data_to_get_bid === step 1 (formatage conditions) :\n',liste_condition,'\n')
    for cond in liste_condition:
        liste_cond.append(cond_to_segment(cond))
    print('\nfrom prepare_data_to_get_bid === step 2 (formatage conditions)\n: ',liste_cond,'\n')


    for cond in liste_cond:

        #segment : elem[8:8+length], recence : supression(' ',elem[23:])
        liste_tuple = [(elem[8:8+length],supression(':',supression(' ',elem[23:]))) for elem in cond] # on récupère correctement les segments grâce à la taille
        liste_tuple_finale.append((i,liste_tuple))
        i+=1
    print('\nfrom prepare_data_to_get_bid === final step (prepare_data ==> OK !) :\n ', liste_tuple_finale, '\n')
    return liste_tuple_finale       # return  : [(regle1, [(segment,recense),(segment,recense)...])] (segment,recense) pour chaque condition de leaf_name1


# load_tree : l'arbre chargé , json_file : Le json_file des bid_matrix, function : max ou moyenne appliqué au calcul des bids
def calcul_bid(load_tree,json_file,function=max):       # obtenir la valeur des bids pour chaque règle de la forme [(regle_value, bid_value),....,(regle_value,0)]

    liste_bid = []
    bid_finale = []
    bid_test = []
    print('\nSTEP 2 ========== PREPARER LES DONNEES ===========\n')
    liste_tuple = prepare_data_to_get_bid(load_tree, json_file)
    print('\nSTEP 3 ========== CALCUL DU NOUVEAU BID ===========\n')
    bid_matrix = json_file["bid_matrix"] # on récupère la bid_matrix
    for k, v in liste_tuple:
        liste_bid = []
        for t in v:
            segment,recence = t
            if (recence =='' and segment == ''):
                liste_bid.append(0)
            else:
                liste_bid.append(float(get_bid(bid_matrix,segment,recence)))
        bid_test.append((k,liste_bid))
        coef = '1.'+str(len(liste_bid))
        bid = function(liste_bid)*float(coef)
        bid_finale.append((k,bid))
    print('\nfrom calcul_bid ===  (liste_bid) :\n',bid_test[0:5],'\n')
    print('\nfrom calcul_bid === final step (bid final) :\n',bid_finale[0:5],'\n')
    return bid_finale

# load_tree : arbre chargé par load_tree
def calcul_weight(load_tree,json_file,segment_recence,function=sum):

    segment_recence_finale = []
    print('\nSTEP 2 ========== PREPARER LES DONNEES ===========\n')
    liste_tuple = prepare_data_to_get_bid(load_tree, json_file)
    print('\nfrom calcul_weight ======== step 1 (prepare_data) liste_tuple : \n', liste_tuple[0:5])
    print('\nSTEP 3 ========== CALCUL DU POIDS ===========\n')
    seg_recence = segment_recence["segment_recence"] # on récupère les segment_recence
    for k, v in liste_tuple:
        liste_segment_recence = []
        for t in v:
            segment,recence = t
            if (recence =='' and segment == ''):
                liste_segment_recence.append(0)
            else:
                liste_segment_recence.append(float(get_segment_recence(seg_recence,segment,recence)))

        poids = function(liste_segment_recence)
        segment_recence_finale.append((k,poids))

    print('\nfrom calcul_weight === final step (segment_recence_finale) :\n',segment_recence_finale,'\n')
    return segment_recence_finale
# segment_recence_finale : [(règle,poids),(règles,poids)...]

# calcul le nouveau bid pour chaque règle. Prend une fonction en paramètre : ex : 'mean', 'max', 'min', 'median' ...
# Reformate
def get_new_bid(tree_load,json_file,function=max):
    bid_finale = calcul_bid(tree_load,json_file,function)
    new_bid=[]
    for k,b in bid_finale:
        if b == 0 :
            bid_text = '\tvalue: no_bid'
        else :
            bid_text = '\tvalue: '+str(b)
        new_bid.append((k,bid_text))
    print('\nfrom get_new_bid (formatage new_bid)\n', new_bid, '\n')
    return new_bid

# récupérer les segments utilisés dans un arbre
def get_sid_from_tree(tree_load,json_file):

    liste_tuple = prepare_data_to_get_bid(tree_load,json_file)
    liste_seg = []
    for t in liste_tuple:
        (k,liste) = t
        for segment,recence in liste:
            if segment == '' or recence == '':
                continue
            if segment not in liste_seg:
                liste_seg.append(segment)
    return liste_seg


def get_new_tree(tree_load,liste_new_bid):
    print('\nSTEP 4 ========== PREPARATION DU NOUVEL ARBRE ===========\n')
    regle,leaf_name,liste_bid = tree_load
    fusion_liste = []
    new_arbre = []
    for elem in regle:
        (k,v) = elem
        if v.find('else') != -1 :
            bid = '\tvalue: no_bid'
            fusion_liste.append(list((v,bid)))
        else :
            for t in leaf_name:
                if k == t[0]:
                    leaf = t[1]
            for t in liste_new_bid:
                if k == t[0]:
                    bid = t[1]
            fusion_liste.append(list((v,leaf,bid))) # on enlève les keys
    for liste in fusion_liste:
        for elem in liste:
            new_arbre.append(elem+'\n')
    print('========== Nouvel arbre correctement généré =========')
    return new_arbre


def save_new_tree(file_name, new_tree):
    print("\nSTEP 5 ========== SAUVEGARDE DE L'ARBRE ===========\n")
    with open(file_name,'w') as f:
        for line in new_tree:
            f.write(line)
    print('================ Nouvel arbre sauvegarder ============== :',file_name)



def main():

    json_file = load_json() # on charge le fichier Json
    tree_load = load_tree() # on charge l'arbre à traiter
    tree_ordered = order_tree(tree_load)
    if new_tree_validation(tree_ordered): # 1ere vérification suite à l'ordonnance de l'arbre
        tree_load = load_tree(tree_ordered)
        liste_new_bid = get_new_bid(tree_load,json_file)
        new_arbre = get_new_tree(tree_load,liste_new_bid)
        if new_tree_validation(new_arbre):                       # Deuxième vérification suite à l'intégration des nouveaux bids
            save_new_tree('Tree_Recommerce_max_ordered_2018_03_16_1', new_arbre)
        else :
            print('Arbre non enregistrer === Problème de création lors de la récupération du bid ')
    else :
        print('Tree ordered not TRUE')

def main2():
    tree_load = load_tree()
    json_file = load_json()
    liste_seg = get_sid_from_tree(tree_load,json_file)
    print(liste_seg)

def tree_bid_not_ordered():

    json_file = load_json() # on charge le fichier Json
    tree_load = load_file() # on charge l'arbre à traiter
    if new_tree_validation(tree_load):
        tree_load = load_tree(tree_load)
        liste_new_bid = get_new_bid(tree_load,json_file) # par defaut , la récupération du bid par le max
        new_arbre = get_new_tree(tree_load,liste_new_bid)
        if new_tree_validation(new_arbre):                       # Deuxième vérification suite à l'intégration des nouveaux bids
            save_new_tree('Tree_SFR_bid_2018_03_15', new_arbre)
        else :
            print('Arbre non enregistrer === Problème de création lors de la récupération du bid ')
    else :
        print('Tree ordered not TRUE')

def tree_bid_ordered_with_weight():

    json_file = load_json() # chargement de la bid_matrix
    tree_load = load_tree() # chargement de l'arbre au format (règle,leaf_name,liste_bid)
    segment_recence_file = load_json_segment_recence() # chargement du json segment_recence_file
    tree_ordered_weight = order_tree_weight(tree_load,json_file,segment_recence_file) # On peut choisir le calcul du poids (somme,moyenne,min,max...) par default : somme
    if new_tree_validation(tree_ordered_weight): # 1ere vérification suite à l'ordonnance de l'arbre
        tree_load = load_tree(tree_ordered_weight) # on charge l'arbre trié avec les poids
        liste_new_bid = get_new_bid(tree_load,json_file,sum) # on lui applique les bids selon la sum
        new_arbre = get_new_tree(tree_load,liste_new_bid)
        if new_tree_validation(new_arbre):                       # Deuxième vérification suite à l'intégration des nouveaux bids
            save_new_tree('Tree_weight_Eurobet_test', new_arbre)
        else :
            print('Arbre non enregistrer === Problème de création lors de la récupération du bid ')
    else :
        print('Tree ordered not TRUE')



if __name__ == '__main__':
    if process == 1 :
        main() #  Arbre ordonné selon la taille et récupération des bids
    if process == 2 :
        tree_bid_ordered_with_weight() # Arbre bid ordonné selon la nouvelle règle des poids
    if process == 3 :
        tree_bid_not_ordered() # Arbre avec bid et non ordonné
    else :
        main2()
