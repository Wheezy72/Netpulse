import { createApp } from "vue";
import App from "./App.vue";
import "./assets/styles.css";

import ECharts from "vue-echarts";
import { use } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";

// Register the ECharts pieces we need. This keeps the bundle smaller than
// loading everything by default.
use([CanvasRenderer, LineChart, GridComponent, TooltipComponent, LegendComponent]);

const app = createApp(App);

// Global chart component used in the Pulse panel (and anywhere else we need charts).
app.component("v-chart", ECharts);

app.mount("#app");