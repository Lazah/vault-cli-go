package internal

type Set[T comparable] struct {
	vals map[T]struct{}
}

func NewSet[T comparable](inputVals ...T) *Set[T] {
	tempMap := make(map[T]struct{})
	set := &Set[T]{
		vals: tempMap,
	}
	set.Add(inputVals...)
	return set
}

func (s *Set[T]) Add(inputVals ...T) {
	for _, v := range inputVals {
		if _, ok := s.vals[v]; !ok {
			s.vals[v] = struct{}{}
		}
	}
}

func (s *Set[T]) GetValues() []T {
	retVal := make([]T, 0)
	for k := range s.vals {
		retVal = append(retVal, k)
	}
	return retVal
}
