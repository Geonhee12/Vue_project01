<template>
  <div id="nav">
    <NavBar />

  </div>

  <div class="container">
    <router-view/>
  </div>

</template>

<script>
import NavBar from '@/components/NavBar'

export default{
  components:{
    NavBar
  }
}
</script>

<style lang="scss">
@import '../node_modules/bootstrap/scss/bootstrap';
</style>
