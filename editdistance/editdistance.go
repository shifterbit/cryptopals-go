package editdistance

import "sort"

type KeysizeEditDistance struct {
	KeySize      int
	EditDistance int
}

type By func(k1, k2 *KeysizeEditDistance) bool

func (by By) Sort(keySizeDistances []KeysizeEditDistance) {
	ks := &keySizeDistanceSorter{
		keySizeDistances: keySizeDistances,
		by:               by,
	}
	sort.Sort(ks)
}

type keySizeDistanceSorter struct {
	keySizeDistances []KeysizeEditDistance
	by               func(k1, k2 *KeysizeEditDistance) bool
}

func (k *keySizeDistanceSorter) Less(i int, j int) bool {
	return k.by(&k.keySizeDistances[i], &k.keySizeDistances[j])
}

func (k *keySizeDistanceSorter) Swap(i int, j int) {
	k.keySizeDistances[i], k.keySizeDistances[j] = k.keySizeDistances[j], k.keySizeDistances[i]
}

func (ks *keySizeDistanceSorter) Len() int {
	return len(ks.keySizeDistances)
}

func ByDistance(k1, k2 *KeysizeEditDistance) bool {
	return k1.EditDistance < k2.EditDistance
}
