<template lang="">

<div class="mt-4">
   <form>
  <div class="mb-3">
    <label for="email" class="form-label">Email address</label>
    <input v-model="form.email" type="email" class="form-control" id="email" aria-describedby="emailHelp">
  </div>
  <div class="mb-3">
    <label for="exampleInputPassword1" class="form-label">Password</label>
    <input v-model="form.email" type="password" class="form-control" id="exampleInputPassword1">
  </div>

  <button @click=onSubmit() type="submit" class="btn btn-primary">Login</button>
</form> 
</div>

</template>
<script>
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
        onSubmit(){
            console.log(this.form.email);
        }
    },
}
</script>
<style lang="">
    
</style>