;;;;;;;;;;;;;;;;
;; Data types ;;
;;;;;;;;;;;;;;;;

;; Simple credential template
;;
(deftemplate credential
  "Generic representation of credential fields"
  (slot id)
  (slot issuer)
  (slot subject)
  (slot fingerprint)
  (slot owned (default false))
  (slot map (default (new java.util.HashMap))))

;; Even simpler credential chain representation
;;
(deftemplate credential-chain
  "Stupid simple credential chain representation"
  (multislot credentials))

;; Representation of a claim
;;
(deftemplate claim
  "Used to hold uncertified claim information"
  (slot id)
  (slot type)
  (slot value))

;; Used to represent a policy satisfaction
;;
(deftemplate satisfaction
  "Holds information about policies that get satisfied"
  (slot resource-name)
  (multislot claims)
  (multislot credentials))

;; Query that selects out satisfaction objects
(defquery get-satisfactions (satisfaction ))


;;;;;;;;;;;;;;;;;;;;;;;
;; Helpful functions ;;
;;;;;;;;;;;;;;;;;;;;;;;

;; Tests if the given item is in a list
(deffunction in-chain (?id $?chain)
  return (neq (member$ ?id ?chain) FALSE))

;; Tests if the given value is the nth item in a list
(deffunction is-nth (?id ?n $?ids)
  return (eq ?id (nth$ ?n ?ids)))

;; Is this the root of a credential chain?
(deffunction is-root (?id $?ids)
  (is-nth ?id 1 $?ids))

;; is this the leaf of a credential chain?
(deffunction is-leaf (?id $?ids)
  (is-nth ?id (length$ ?ids) $?ids))

;; Removes duplicate items from a list
(deffunction dup-elim ($?items)
  (bind ?new-list (create$ (nth$ 1 ?items)))
  (bind ?idx 2)
  (foreach ?i ?items
    (if (eq (member$ ?i ?new-list) FALSE) then
      (bind ?new-list (insert$ ?new-list ?idx ?i))
      (bind ?idx (+ ?idx 1))))
  (return ?new-list))
