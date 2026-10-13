import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from './types';

export type RootNavigation = NativeStackNavigationProp<RootStackParamList>;

/** Typed navigation for stack screens. */
export function useRootNavigation(): RootNavigation {
  return useNavigation<RootNavigation>();
}
