declare module 'vue-virtual-scroller' {
  import type { DefineComponent, SlotsType } from 'vue'

  export const RecycleScroller: DefineComponent<
    { items: any[]; itemSize: number; keyField?: string; [key: string]: any },
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    string,
    {},
    {},
    {},
    SlotsType<{ default: { item: any; index: number; active: boolean } }>
  >
  export const DynamicScroller: DefineComponent<any, any, any>
  export const DynamicScrollerItem: DefineComponent<any, any, any>
}

declare module 'splitpanes' {
  import type { DefineComponent } from 'vue'
  export const Splitpanes: DefineComponent<any, any, any>
  export const Pane: DefineComponent<any, any, any>
}
