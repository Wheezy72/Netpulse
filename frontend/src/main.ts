import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import router from "./router";
import { installAuthInterceptor } from "./utils/authInterceptor";
import "./assets/styles.css";

import ECharts from "vue-echarts";
import { use } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { BarChart, GaugeChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";

use([
  CanvasRenderer,
  BarChart,
  GaugeChart,
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
]);

const app = createApp(App);

const pinia = createPinia();
app.use(pinia);
app.use(router);

// An expired token (60 minutes when "Remember me" is unchecked) must return
// to the sign-in screen instead of leaving every panel half-loaded.
installAuthInterceptor(router, pinia);

app.component("v-chart", ECharts);

app.mount("#app");