<template lang="">

<div class="mt-4">
   <form @submit.prevent="onSubmit">
  <div class="mb-3">
    <label for="email" class="form-label">Email address</label>
    <input v-model="form.email" type="email" class="form-control" id="email" aria-describedby="emailHelp">
  </div>
  <div class="mb-3">
    <label for="exampleInputPassword1" class="form-label">Password</label>
    <input v-model="form.password" type="password" class="form-control" id="exampleInputPassword1">
  </div>

  <button type="submit" class="btn btn-primary">Login</button>
</form> 
</div>

</template>
<script>
import axios from 'axios'
export default {
    data() {
        return {
            form:{
                email:'',
                password:''
            }
        }
    },
    methods: {
        async onSubmit(){
          try{
            await axios.post('http://localhost:3000/login', {
            email: this.form.email,
            password: this.form.password})

            this.$router.push({path:'/'})

          }
          

          catch(err){
            console.log(err);   
          }

      
        }
    },
}
</script>
<style lang="">
    
</style>